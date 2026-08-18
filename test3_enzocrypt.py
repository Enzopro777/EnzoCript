import os
import sys
import time
import hashlib
import tempfile
import importlib.util


# ============================================================
# CONFIGURACIÓN
# ============================================================

APP_NAME = "app1.0.5.py"

PASSWORD = b"EnzoCrypt_Chunk_Test_2026!"

CHUNK_SIZE = 8 * 1024 * 1024  # 8 MB

TEST_SIZE = 1 * 1024 * 1024 * 1024  # 1 GB

KEEP_FILES = False


# ============================================================
# CARGAR ENZOCRYPT
# ============================================================

APP_FILE = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    APP_NAME
)

if not os.path.exists(APP_FILE):
    print(f"ERROR: No se encontró {APP_NAME}")
    print(APP_FILE)
    sys.exit(1)


spec = importlib.util.spec_from_file_location(
    "enzocrypt",
    APP_FILE
)

enzocrypt = importlib.util.module_from_spec(spec)
spec.loader.exec_module(enzocrypt)


# ============================================================
# UTILIDADES
# ============================================================

def sha256_file(path):

    h = hashlib.sha256()

    with open(path, "rb") as f:

        while True:

            data = f.read(8 * 1024 * 1024)

            if not data:
                break

            h.update(data)

    return h.hexdigest()


def create_test_file(path, size):

    """
    Genera un archivo determinista.
    """

    pattern = bytes(range(256))

    with open(path, "wb") as f:

        remaining = size

        while remaining:

            amount = min(
                8 * 1024 * 1024,
                remaining
            )

            repeats = (
                amount // len(pattern)
            ) + 1

            block = (
                pattern * repeats
            )[:amount]

            f.write(block)

            remaining -= amount


def write_u32_le(f, value):

    f.write(
        int(value).to_bytes(
            4,
            "little"
        )
    )


def read_u32(data, offset):

    return int.from_bytes(
        data[offset:offset + 4],
        "little"
    )


# ============================================================
# PARSER DE V2
# ============================================================

def parse_v2(path):

    """
    Lee la estructura del archivo V2 sin descifrarlo.

    Estructura esperada:

        MAGIC
        VERSION
        EXT_LEN
        EXT
        RSA_LEN
        RSA_BLOB
        CHUNK_SIZE

        CHUNK:
            CHUNK_LEN
            NONCE
            TAG
            CIPHERTEXT
    """

    chunks = []

    with open(path, "rb") as f:

        # ----------------------------------------------------
        # MAGIC
        # ----------------------------------------------------

        magic_pos = f.tell()
        magic = f.read(4)

        if len(magic) != 4:
            raise ValueError("MAGIC incompleto")

        # ----------------------------------------------------
        # VERSION
        # ----------------------------------------------------

        version_pos = f.tell()
        version = f.read(2)

        if len(version) != 2:
            raise ValueError("VERSION incompleta")

        # ----------------------------------------------------
        # EXTENSION
        # ----------------------------------------------------

        ext_len_pos = f.tell()
        ext_len_raw = f.read(1)

        if len(ext_len_raw) != 1:
            raise ValueError("EXT_LEN incompleto")

        ext_len = ext_len_raw[0]

        ext_pos = f.tell()
        ext = f.read(ext_len)

        if len(ext) != ext_len:
            raise ValueError("EXT incompleta")

        # ----------------------------------------------------
        # RSA BLOB
        # ----------------------------------------------------

        rsa_len_pos = f.tell()
        rsa_len_raw = f.read(2)

        if len(rsa_len_raw) != 2:
            raise ValueError("RSA_LEN incompleto")

        rsa_len = int.from_bytes(
            rsa_len_raw,
            "little"
        )

        rsa_pos = f.tell()
        rsa_blob = f.read(rsa_len)

        if len(rsa_blob) != rsa_len:
            raise ValueError("RSA blob incompleto")

        # ----------------------------------------------------
        # CHUNK SIZE
        # ----------------------------------------------------

        chunk_size_pos = f.tell()
        chunk_size_raw = f.read(4)

        if len(chunk_size_raw) != 4:
            raise ValueError("CHUNK_SIZE incompleto")

        chunk_size = int.from_bytes(
            chunk_size_raw,
            "little"
        )

        header_end = f.tell()

        # ----------------------------------------------------
        # CHUNKS
        # ----------------------------------------------------

        index = 0

        while True:

            chunk_start = f.tell()

            raw_len = f.read(4)

            if not raw_len:
                break

            if len(raw_len) != 4:
                raise ValueError(
                    f"Chunk {index}: longitud incompleta"
                )

            chunk_len = int.from_bytes(
                raw_len,
                "little"
            )

            nonce_pos = f.tell()
            nonce = f.read(12)

            if len(nonce) != 12:
                raise ValueError(
                    f"Chunk {index}: nonce incompleto"
                )

            tag_pos = f.tell()
            tag = f.read(16)

            if len(tag) != 16:
                raise ValueError(
                    f"Chunk {index}: tag incompleto"
                )

            ciphertext_pos = f.tell()

            ciphertext = f.read(chunk_len)

            if len(ciphertext) != chunk_len:
                raise ValueError(
                    f"Chunk {index}: ciphertext incompleto"
                )

            chunk_end = f.tell()

            chunks.append({
                "index": index,
                "start": chunk_start,
                "end": chunk_end,

                "length_pos": chunk_start,
                "length": chunk_len,

                "nonce_pos": nonce_pos,
                "tag_pos": tag_pos,
                "ciphertext_pos": ciphertext_pos,

                "ciphertext_length": chunk_len,

                "total_size": (
                    4 +
                    12 +
                    16 +
                    chunk_len
                )
            })

            index += 1

    return {
        "magic_pos": magic_pos,
        "version_pos": version_pos,

        "ext_len_pos": ext_len_pos,
        "ext_pos": ext_pos,

        "rsa_len_pos": rsa_len_pos,
        "rsa_pos": rsa_pos,

        "chunk_size_pos": chunk_size_pos,

        "header_end": header_end,

        "magic": magic,
        "version": version,

        "chunk_size": chunk_size,

        "chunks": chunks
    }


# ============================================================
# CORROMPER UN BYTE Y RESTAURARLO
# ============================================================

def corrupt_byte(path, position):

    with open(path, "r+b") as f:

        f.seek(position)

        original = f.read(1)

        if len(original) != 1:
            raise ValueError(
                f"No se pudo leer byte en {position}"
            )

        corrupted = bytes([
            original[0] ^ 0x01
        ])

        f.seek(position)
        f.write(corrupted)
        f.flush()

    return original


def restore_byte(path, position, original):

    with open(path, "r+b") as f:

        f.seek(position)
        f.write(original)
        f.flush()


# ============================================================
# INTENTO DE DESCIFRADO
# ============================================================

def attempt_decrypt(
    container,
    private_key,
    output
):

    if os.path.exists(output):
        os.remove(output)

    start = time.perf_counter()

    accepted = False
    error = None

    try:

        enzocrypt.decrypt_file_v2(
            container,
            private_key,
            PASSWORD,
            output
        )

        accepted = True

    except Exception as e:

        error = e

    elapsed = time.perf_counter() - start

    output_exists = os.path.exists(output)

    output_size = (
        os.path.getsize(output)
        if output_exists
        else 0
    )

    return {
        "accepted": accepted,
        "error": error,
        "elapsed": elapsed,
        "output_exists": output_exists,
        "output_size": output_size
    }


# ============================================================
# TEST DE CORRUPCIÓN
# ============================================================

def test_corruption(
    label,
    container,
    position,
    private_key,
    output
):

    original_byte = corrupt_byte(
        container,
        position
    )

    result = attempt_decrypt(
        container,
        private_key,
        output
    )

    restore_byte(
        container,
        position,
        original_byte
    )

    # --------------------------------------------------------
    # SI ACEPTÓ EL ARCHIVO CORRUPTO → FAIL
    # --------------------------------------------------------

    if result["accepted"]:

        print(
            f"[FAIL] {label}"
        )

        print(
            "       ¡EnzoCrypt aceptó datos corruptos!"
        )

        print(
            f"       Output: "
            f"{result['output_size']} bytes"
        )

        return False

    # --------------------------------------------------------
    # RECHAZÓ
    # --------------------------------------------------------

    print(
        f"[PASS] {label}"
    )

    print(
        f"       Corrupción rechazada "
        f"({result['elapsed']:.2f}s)"
    )

    if result["output_exists"]:

        print(
            f"       ⚠️ Quedó archivo parcial: "
            f"{result['output_size']} bytes"
        )

        os.remove(output)

    return True


# ============================================================
# INTERCAMBIAR CHUNKS
# ============================================================

def swap_chunks(
    path,
    chunk_a,
    chunk_b
):

    if chunk_a["total_size"] != chunk_b["total_size"]:

        raise ValueError(
            "Los chunks tienen tamaños diferentes; "
            "no se pueden intercambiar in-place."
        )

    size = chunk_a["total_size"]

    with open(path, "r+b") as f:

        f.seek(chunk_a["start"])
        a = f.read(size)

        f.seek(chunk_b["start"])
        b = f.read(size)

        f.seek(chunk_a["start"])
        f.write(b)

        f.seek(chunk_b["start"])
        f.write(a)

        f.flush()


# ============================================================
# TEST ORDEN DE CHUNKS
# ============================================================

def test_chunk_swap(
    container,
    chunks,
    private_key,
    output
):

    print()
    print(
        "Probando intercambio de chunks..."
    )

    if len(chunks) < 2:

        print(
            "[SKIP] El archivo no contiene "
            "al menos dos chunks."
        )

        return None

    # Los dos primeros chunks deberían tener
    # el mismo tamaño en un archivo de 1 GB
    # con chunks de 8 MB.

    a = chunks[0]
    b = chunks[1]

    if a["total_size"] != b["total_size"]:

        print(
            "[SKIP] Los dos primeros chunks "
            "no tienen el mismo tamaño."
        )

        return None

    swap_chunks(
        container,
        a,
        b
    )

    result = attempt_decrypt(
        container,
        private_key,
        output
    )

    # Restaurar el archivo inmediatamente.
    swap_chunks(
        container,
        a,
        b
    )

    if result["accepted"]:

        print(
            "[FAIL] INTERCAMBIO DE CHUNKS"
        )

        print(
            "       ¡EnzoCrypt aceptó los chunks "
            "en un orden incorrecto!"
        )

        if os.path.exists(output):
            os.remove(output)

        return False

    print(
        "[PASS] INTERCAMBIO DE CHUNKS"
    )

    print(
        "       El orden incorrecto fue rechazado."
    )

    if result["output_exists"]:

        print(
            f"       ⚠️ Quedó archivo parcial: "
            f"{result['output_size']} bytes"
        )

        os.remove(output)

    return True


# ============================================================
# MAIN
# ============================================================

def main():

    print()
    print(
        "╔══════════════════════════════════════════════════════════╗"
    )
    print(
        "║       ENZOCRYPT V2 — CHUNK INTEGRITY TEST              ║"
    )
    print(
        "║                    1 GB TEST                           ║"
    )
    print(
        "╚══════════════════════════════════════════════════════════╝"
    )

    print()
    print(
        "Esta prueba creará un archivo de 1 GB."
    )

    print(
        "Después modificará temporalmente diferentes bytes"
    )

    print(
        "del contenedor y comprobará que el descifrado"
    )

    print(
        "rechace todas las alteraciones."
    )

    print()

    with tempfile.TemporaryDirectory(
        prefix="EnzoCryptChunkTest_"
    ) as workdir:

        original = os.path.join(
            workdir,
            "original_1GB.bin"
        )

        container = os.path.join(
            workdir,
            "original_1GB.enzocrypt"
        )

        output = os.path.join(
            workdir,
            "decrypted.bin"
        )

        keys = os.path.join(
            workdir,
            "keys"
        )

        os.makedirs(keys)

        # ----------------------------------------------------
        # GENERAR CLAVES
        # ----------------------------------------------------

        print(
            "[1/6] Generando identidad..."
        )

        private_key, public_key = (
            enzocrypt.generate_identity(
                keys,
                "chunk_test",
                PASSWORD
            )
        )

        print(
            "[PASS] Identidad generada."
        )

        # ----------------------------------------------------
        # CREAR 1 GB
        # ----------------------------------------------------

        print()
        print(
            "[2/6] Creando archivo de 1 GB..."
        )

        start = time.perf_counter()

        create_test_file(
            original,
            TEST_SIZE
        )

        elapsed = time.perf_counter() - start

        print(
            f"[PASS] Archivo creado "
            f"({elapsed:.2f}s)"
        )

        # ----------------------------------------------------
        # HASH ORIGINAL
        # ----------------------------------------------------

        print()
        print(
            "[3/6] Calculando SHA-256..."
        )

        original_hash = sha256_file(
            original
        )

        print(
            f"[PASS] {original_hash}"
        )

        # ----------------------------------------------------
        # CIFRAR
        # ----------------------------------------------------

        print()
        print(
            "[4/6] Cifrando 1 GB..."
        )

        start = time.perf_counter()

        enzocrypt.encrypt_file_v2(
            original,
            public_key,
            container,
            CHUNK_SIZE
        )

        elapsed = time.perf_counter() - start

        print(
            f"[PASS] Contenedor creado "
            f"({elapsed:.2f}s)"
        )

        # ----------------------------------------------------
        # ANALIZAR CHUNKS
        # ----------------------------------------------------

        print()
        print(
            "[5/6] Analizando chunks..."
        )

        info = parse_v2(
            container
        )

        chunks = info["chunks"]

        print(
            f"[PASS] Chunks encontrados: "
            f"{len(chunks)}"
        )

        print(
            f"      Chunk size declarado: "
            f"{info['chunk_size'] / 1024 / 1024:.2f} MB"
        )

        print(
            f"      Header termina en: "
            f"{info['header_end']} bytes"
        )

        # ----------------------------------------------------
        # PRUEBAS
        # ----------------------------------------------------

        print()
        print(
            "[6/6] EJECUTANDO ATAQUES DE CORRUPCIÓN"
        )

        print()

        total = 0
        passed = 0
        failed = 0

        def run(label, position):

            nonlocal total
            nonlocal passed
            nonlocal failed

            total += 1

            ok = test_corruption(
                label,
                container,
                position,
                private_key,
                output
            )

            if ok:
                passed += 1
            else:
                failed += 1

        # ====================================================
        # CABECERA
        # ====================================================

        run(
            "MAGIC",
            info["magic_pos"]
        )

        run(
            "VERSION",
            info["version_pos"]
        )

        run(
            "EXTENSION",
            info["ext_pos"]
        )

        run(
            "RSA BLOB",
            info["rsa_pos"]
        )

        run(
            "CHUNK SIZE",
            info["chunk_size_pos"]
        )

        # ====================================================
        # PRIMER CHUNK
        # ====================================================

        first = chunks[0]

        run(
            "CHUNK 0 — LENGTH",
            first["length"]
        )

        run(
            "CHUNK 0 — NONCE",
            first["nonce_pos"]
        )

        run(
            "CHUNK 0 — TAG",
            first["tag_pos"]
        )

        run(
            "CHUNK 0 — CIPHERTEXT INICIO",
            first["ciphertext_pos"]
        )

        run(
            "CHUNK 0 — CIPHERTEXT MITAD",
            first["ciphertext_pos"]
            + first["ciphertext_length"] // 2
        )

        run(
            "CHUNK 0 — CIPHERTEXT FINAL",
            first["ciphertext_pos"]
            + first["ciphertext_length"]
            - 1
        )

        # ====================================================
        # CHUNKS INTERNOS
        # ====================================================

        selected_indexes = [
            1,
            2,
            10,
            50,
            100,
            len(chunks) - 1
        ]

        selected_indexes = sorted(
            set(
                i for i in selected_indexes
                if 0 <= i < len(chunks)
            )
        )

        for i in selected_indexes:

            chunk = chunks[i]

            run(
                f"CHUNK {i} — NONCE",
                chunk["nonce_pos"]
            )

            run(
                f"CHUNK {i} — TAG",
                chunk["tag_pos"]
            )

            run(
                f"CHUNK {i} — CIPHERTEXT MITAD",
                chunk["ciphertext_pos"]
                + chunk["ciphertext_length"] // 2
            )

        # ====================================================
        # INTERCAMBIO DE CHUNKS
        # ====================================================

        swap_result = test_chunk_swap(
            container,
            chunks,
            private_key,
            output
        )

        if swap_result is not None:

            total += 1

            if swap_result:
                passed += 1
            else:
                failed += 1

        # ====================================================
        # RESULTADO
        # ====================================================

        print()
        print(
            "╔══════════════════════════════════════════════════════════╗"
        )
        print(
            "║                    RESULTADO                           ║"
        )
        print(
            "╚══════════════════════════════════════════════════════════╝"
        )

        print()

        print(
            f"Pruebas ejecutadas : {total}"
        )

        print(
            f"Superadas          : {passed}"
        )

        print(
            f"Fallidas           : {failed}"
        )

        print()

        if failed == 0:

            print(
                "🎉 TODAS LAS CORRUPCIONES FUERON RECHAZADAS."
            )

            print()
            print(
                "La prueba de integridad de chunks fue superada."
            )

        else:

            print(
                "❌ HAY CORRUPCIONES QUE ENZOCRYPT ACEPTÓ."
            )

            print()
            print(
                "NO consideres esta versión lista para publicar."
            )

            return 1

        # ====================================================
        # ARCHIVOS
        # ====================================================

        if KEEP_FILES:

            print()
            print(
                "Archivos conservados en:"
            )

            print(
                workdir
            )

            input(
                "Presiona ENTER para terminar..."
            )

    return 0


if __name__ == "__main__":

    sys.exit(
        main()
    )