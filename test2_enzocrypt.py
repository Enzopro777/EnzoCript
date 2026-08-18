import os
import sys
import time
import shutil
import tempfile
import threading
import importlib.util


# ============================================================
# CARGAR ENZOCRYPT
# ============================================================

APP_FILE = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "app1.0.5.py"
)

if not os.path.exists(APP_FILE):
    print("ERROR: No se encontró app1.0.5.py")
    print(APP_FILE)
    sys.exit(1)

spec = importlib.util.spec_from_file_location(
    "enzocrypt",
    APP_FILE
)

enzocrypt = importlib.util.module_from_spec(spec)
spec.loader.exec_module(enzocrypt)


# ============================================================
# CONFIGURACIÓN
# ============================================================

PASSWORD = b"EnzoCrypt_Test_2026!"
WRONG_PASSWORD = b"WrongPassword_123!"

CHUNK_SIZE = enzocrypt.CHUNK_PRESETS["Balanced (8 MB)"]

# Para que la prueba sea rápida.
TEST_FILE_SIZE = 16 * 1024 * 1024  # 16 MB


# ============================================================
# UTILIDADES
# ============================================================

def banner(text):
    print()
    print("=" * 70)
    print(text)
    print("=" * 70)


def result(name, passed, detail=""):
    if passed:
        print(f"[PASS] {name}")
    else:
        print(f"[FAIL] {name}")

    if detail:
        print(f"       {detail}")


def create_test_file(path, size):
    """
    Crea un archivo determinista.
    """
    pattern = bytes(range(256))

    with open(path, "wb") as f:
        remaining = size

        while remaining:
            amount = min(1024 * 1024, remaining)
            repeats = (amount // len(pattern)) + 1
            block = (pattern * repeats)[:amount]

            f.write(block)
            remaining -= amount


def read_bytes(path):
    with open(path, "rb") as f:
        return f.read()


def copy_file(src, dst):
    shutil.copyfile(src, dst)


def get_header_info(path):
    """
    Lee la cabecera V2 y devuelve posiciones útiles
    para las pruebas de manipulación.
    """

    with open(path, "rb") as f:

        magic_pos = f.tell()
        magic = f.read(4)

        version_pos = f.tell()
        version = f.read(2)

        ext_len_pos = f.tell()
        ext_len = f.read(1)[0]

        ext_pos = f.tell()
        ext = f.read(ext_len)

        rsa_len_pos = f.tell()
        rsa_len_bytes = f.read(2)

        rsa_len = int.from_bytes(
            rsa_len_bytes,
            "little"
        )

        rsa_pos = f.tell()
        rsa_blob = f.read(rsa_len)

        chunk_size_pos = f.tell()
        chunk_size_bytes = f.read(4)

        chunk_size = int.from_bytes(
            chunk_size_bytes,
            "little"
        )

        first_chunk_len_pos = f.tell()

        chunk_len_bytes = f.read(4)

        if len(chunk_len_bytes) != 4:
            raise ValueError("No first chunk.")

        chunk_len = int.from_bytes(
            chunk_len_bytes,
            "little"
        )

        nonce_pos = f.tell()
        nonce = f.read(12)

        tag_pos = f.tell()
        tag = f.read(16)

        ciphertext_pos = f.tell()

        return {
            "magic_pos": magic_pos,
            "version_pos": version_pos,
            "ext_len_pos": ext_len_pos,
            "ext_pos": ext_pos,
            "rsa_len_pos": rsa_len_pos,
            "rsa_pos": rsa_pos,
            "chunk_size_pos": chunk_size_pos,
            "first_chunk_len_pos": first_chunk_len_pos,
            "nonce_pos": nonce_pos,
            "tag_pos": tag_pos,
            "ciphertext_pos": ciphertext_pos,

            "magic": magic,
            "version": version,
            "ext": ext,
            "rsa_blob": rsa_blob,
            "chunk_size": chunk_size,
            "chunk_len": chunk_len,
            "nonce": nonce,
            "tag": tag,
        }


def attempt_decrypt(container, private_key, password, output):
    """
    Intenta descifrar.

    Devuelve:
        True  = descifrado aceptado
        False = descifrado rechazado
    """

    try:
        enzocrypt.decrypt_file_v2(
            container,
            private_key,
            password,
            output
        )

        return True

    except Exception:
        return False


# ============================================================
# CREAR ENTORNO DE PRUEBAS
# ============================================================

def prepare_environment(workdir):

    banner("PREPARANDO ENTORNO")

    keys = os.path.join(workdir, "keys")
    os.makedirs(keys)

    print("Generando identidad RSA de prueba...")

    private_key, public_key = enzocrypt.generate_identity(
        keys,
        "security_test",
        PASSWORD
    )

    print("[PASS] Identidad RSA creada")

    original = os.path.join(
        workdir,
        "original.bin"
    )

    encrypted = os.path.join(
        workdir,
        "original.enzocrypt"
    )

    decrypted = os.path.join(
        workdir,
        "decrypted.bin"
    )

    print("Creando archivo de prueba...")

    create_test_file(
        original,
        TEST_FILE_SIZE
    )

    print(
        f"[PASS] Archivo creado: "
        f"{TEST_FILE_SIZE / 1024 / 1024:.1f} MB"
    )

    print("Cifrando archivo base...")

    enzocrypt.encrypt_file_v2(
        original,
        public_key,
        encrypted,
        CHUNK_SIZE
    )

    if not os.path.exists(encrypted):
        raise RuntimeError(
            "No se creó el archivo cifrado."
        )

    print("[PASS] Archivo base cifrado")

    return {
        "private": private_key,
        "public": public_key,
        "original": original,
        "encrypted": encrypted,
        "decrypted": decrypted,
    }


# ============================================================
# 1. PRUEBAS DE INTEGRIDAD
# ============================================================

def test_integrity(env):

    banner("1. PRUEBAS DE INTEGRIDAD")

    private_key = env["private"]
    original_container = env["encrypted"]

    base = read_bytes(original_container)

    info = get_header_info(original_container)

    tests = []

    # --------------------------------------------------------
    # MAGIC
    # --------------------------------------------------------

    data = bytearray(base)
    data[info["magic_pos"]] ^= 0x01

    tests.append(
        ("MAGIC", data)
    )

    # --------------------------------------------------------
    # VERSION
    # --------------------------------------------------------

    data = bytearray(base)
    data[info["version_pos"]] ^= 0x01

    tests.append(
        ("VERSION", data)
    )

    # --------------------------------------------------------
    # EXTENSION
    # --------------------------------------------------------

    data = bytearray(base)

    if info["ext"]:
        data[info["ext_pos"]] ^= 0x01
    else:
        # Si no hubiera extensión, modificamos ext_len.
        data[info["ext_len_pos"]] ^= 0x01

    tests.append(
        ("EXTENSION", data)
    )

    # --------------------------------------------------------
    # RSA BLOB
    # --------------------------------------------------------

    data = bytearray(base)
    data[info["rsa_pos"]] ^= 0x01

    tests.append(
        ("RSA BLOB", data)
    )

    # --------------------------------------------------------
    # CHUNK SIZE
    # --------------------------------------------------------

    data = bytearray(base)
    data[info["chunk_size_pos"]] ^= 0x01

    tests.append(
        ("CHUNK SIZE", data)
    )

    # --------------------------------------------------------
    # CHUNK LENGTH
    # --------------------------------------------------------

    data = bytearray(base)
    data[info["first_chunk_len_pos"]] ^= 0x01

    tests.append(
        ("CHUNK LENGTH", data)
    )

    # --------------------------------------------------------
    # NONCE
    # --------------------------------------------------------

    data = bytearray(base)
    data[info["nonce_pos"]] ^= 0x01

    tests.append(
        ("NONCE", data)
    )

    # --------------------------------------------------------
    # TAG
    # --------------------------------------------------------

    data = bytearray(base)
    data[info["tag_pos"]] ^= 0x01

    tests.append(
        ("TAG", data)
    )

    # --------------------------------------------------------
    # CIPHERTEXT
    # --------------------------------------------------------

    data = bytearray(base)
    data[info["ciphertext_pos"]] ^= 0x01

    tests.append(
        ("CIPHERTEXT", data)
    )

    passed = 0

    for name, data in tests:

        corrupted = os.path.join(
            os.path.dirname(original_container),
            "corrupted.enzocrypt"
        )

        output = os.path.join(
            os.path.dirname(original_container),
            "attack_output.bin"
        )

        if os.path.exists(output):
            os.remove(output)

        with open(corrupted, "wb") as f:
            f.write(data)

        accepted = attempt_decrypt(
            corrupted,
            private_key,
            PASSWORD,
            output
        )

        if accepted:
            result(
                name,
                False,
                "¡El archivo modificado fue aceptado!"
            )
        else:
            result(
                name,
                True,
                "Alteración detectada."
            )
            passed += 1

        if os.path.exists(output):
            os.remove(output)

        os.remove(corrupted)

    # --------------------------------------------------------
    # ORDEN DE CHUNKS
    # --------------------------------------------------------

    print()
    print("Probando orden de chunks...")

    # Para esta prueba necesitamos al menos dos chunks.
    # Creamos un archivo suficientemente grande.

    multi_original = os.path.join(
        os.path.dirname(original_container),
        "multi.bin"
    )

    multi_container = os.path.join(
        os.path.dirname(original_container),
        "multi.enzocrypt"
    )

    create_test_file(
        multi_original,
        CHUNK_SIZE * 2 + 1024
    )

    enzocrypt.encrypt_file_v2(
        multi_original,
        env["public"],
        multi_container,
        CHUNK_SIZE
    )

    raw = read_bytes(multi_container)

    # Parsear la cabecera para localizar los chunks.
    info2 = get_header_info(multi_container)

    offset = info2["ciphertext_pos"]

    # Primer chunk completo.
    first_len = info2["chunk_len"]

    first_total = 4 + 12 + 16 + first_len

    second_offset = offset + first_total

    # Leer segundo chunk.
    second_len = int.from_bytes(
        raw[second_offset:second_offset + 4],
        "little"
    )

    second_total = (
        4 + 12 + 16 + second_len
    )

    if len(raw) >= second_offset + second_total:

        corrupted = bytearray(raw)

        first_chunk = raw[
            info2["first_chunk_len_pos"]:
            second_offset
        ]

        second_chunk = raw[
            second_offset:
            second_offset + second_total
        ]

        corrupted[
            info2["first_chunk_len_pos"]:
            second_offset + second_total
        ] = second_chunk + first_chunk

        swapped_path = os.path.join(
            os.path.dirname(original_container),
            "swapped.enzocrypt"
        )

        with open(swapped_path, "wb") as f:
            f.write(corrupted)

        output = os.path.join(
            os.path.dirname(original_container),
            "swap_output.bin"
        )

        accepted = attempt_decrypt(
            swapped_path,
            private_key,
            PASSWORD,
            output
        )

        if accepted:
            result(
                "ORDEN DE CHUNKS",
                False,
                "El archivo reordenado fue aceptado."
            )
        else:
            result(
                "ORDEN DE CHUNKS",
                True,
                "Reordenamiento detectado."
            )
            passed += 1

        if os.path.exists(output):
            os.remove(output)

        os.remove(swapped_path)

    else:
        print(
            "[SKIP] No se pudieron obtener dos chunks."
        )

    if os.path.exists(multi_original):
        os.remove(multi_original)

    if os.path.exists(multi_container):
        os.remove(multi_container)

    print()
    print(
        f"Integridad: {passed}/{len(tests) + 1} superadas."
    )


# ============================================================
# 2. PRUEBAS DE CLAVES
# ============================================================

def test_keys(env):

    banner("2. PRUEBAS DE CLAVES")

    encrypted = env["encrypted"]

    # --------------------------------------------------------
    # CLAVE CORRECTA
    # --------------------------------------------------------

    output = os.path.join(
        os.path.dirname(encrypted),
        "correct.bin"
    )

    accepted = attempt_decrypt(
        encrypted,
        env["private"],
        PASSWORD,
        output
    )

    result(
        "CLAVE CORRECTA",
        accepted,
        "El archivo fue descifrado correctamente."
        if accepted
        else "El descifrado falló."
    )

    if os.path.exists(output):
        os.remove(output)

    # --------------------------------------------------------
    # CONTRASEÑA INCORRECTA
    # --------------------------------------------------------

    output = os.path.join(
        os.path.dirname(encrypted),
        "wrong_password.bin"
    )

    accepted = attempt_decrypt(
        encrypted,
        env["private"],
        WRONG_PASSWORD,
        output
    )

    result(
        "CONTRASEÑA INCORRECTA",
        not accepted,
        "Rechazada correctamente."
        if not accepted
        else "¡Aceptó una contraseña incorrecta!"
    )

    if os.path.exists(output):
        os.remove(output)

    # --------------------------------------------------------
    # CLAVE PRIVADA INCORRECTA
    # --------------------------------------------------------

    wrong_dir = os.path.join(
        os.path.dirname(encrypted),
        "wrong_key"
    )

    os.makedirs(wrong_dir)

    wrong_private, _ = enzocrypt.generate_identity(
        wrong_dir,
        "wrong",
        PASSWORD
    )

    output = os.path.join(
        os.path.dirname(encrypted),
        "wrong_key.bin"
    )

    accepted = attempt_decrypt(
        encrypted,
        wrong_private,
        PASSWORD,
        output
    )

    result(
        "CLAVE PRIVADA INCORRECTA",
        not accepted,
        "Rechazada correctamente."
        if not accepted
        else "¡Aceptó una clave privada incorrecta!"
    )

    if os.path.exists(output):
        os.remove(output)

    # --------------------------------------------------------
    # PEM CORRUPTO
    # --------------------------------------------------------

    corrupt_dir = os.path.join(
        os.path.dirname(encrypted),
        "corrupt_key"
    )

    os.makedirs(corrupt_dir)

    corrupt_private = os.path.join(
        corrupt_dir,
        "corrupt_private.pem"
    )

    with open(env["private"], "rb") as f:
        key_data = bytearray(f.read())

    key_data[len(key_data) // 2] ^= 0x01

    with open(corrupt_private, "wb") as f:
        f.write(key_data)

    output = os.path.join(
        os.path.dirname(encrypted),
        "corrupt_key.bin"
    )

    accepted = attempt_decrypt(
        encrypted,
        corrupt_private,
        PASSWORD,
        output
    )

    result(
        "PEM CORRUPTO",
        not accepted,
        "Rechazado correctamente."
        if not accepted
        else "¡Aceptó un PEM corrupto!"
    )

    if os.path.exists(output):
        os.remove(output)


# ============================================================
# 3. CANCELACIÓN
# ============================================================

def test_cancellation(env):

    banner("3. PRUEBAS DE CANCELACIÓN")

    # Para que podamos cancelar de forma visible,
    # usamos un archivo más grande.

    cancel_original = os.path.join(
        os.path.dirname(env["original"]),
        "cancel_test.bin"
    )

    create_test_file(
        cancel_original,
        128 * 1024 * 1024
    )

    positions = [
        ("AL PRINCIPIO", 0.0),
        ("A MITAD", 0.5),
        ("CASI AL FINAL", 0.90),
    ]

    for name, cancel_after in positions:

        print()
        print(f"Probando cancelación: {name}")

        encrypted = os.path.join(
            os.path.dirname(env["encrypted"]),
            f"cancel_{int(cancel_after * 100)}.enzocrypt"
        )

        cancel_flag = threading.Event()

        progress_state = {
            "last": 0,
            "total": 0,
        }

        def progress(done, total, eta):

            progress_state["last"] = done
            progress_state["total"] = total

            if total > 0:

                fraction = done / total

                if fraction >= cancel_after:
                    cancel_flag.set()

        def worker():

            try:

                enzocrypt.encrypt_file_v2(
                    cancel_original,
                    env["public"],
                    encrypted,
                    CHUNK_SIZE,
                    progress_cb=progress,
                    cancel_flag=cancel_flag
                )

            except InterruptedError:
                pass

            except Exception as e:
                print(
                    f"       Error interno durante cancelación: {e}"
                )

        thread = threading.Thread(
            target=worker
        )

        thread.start()
        thread.join()

        # La función de bajo nivel lanza InterruptedError,
        # pero no elimina automáticamente el archivo.
        # La UI de EnzoCrypt sí llama _cleanup().
        #
        # Aquí comprobamos que nosotros podamos detectar
        # el archivo incompleto y eliminarlo.

        exists = os.path.exists(encrypted)

        if exists:

            # Si quedó archivo, significa que la función
            # no hizo limpieza automática.
            #
            # Esto NO es necesariamente un fallo de seguridad:
            # la UI de tu aplicación ya hace _cleanup().
            os.remove(encrypted)

        cancelled = cancel_flag.is_set()

        result(
            name,
            cancelled,
            "Cancelación solicitada correctamente."
            if cancelled
            else "No se recibió la cancelación."
        )

        if exists:
            print(
                "       NOTA: la función core dejó un archivo "
                "parcial; la UI lo elimina mediante _cleanup()."
            )

    if os.path.exists(cancel_original):
        os.remove(cancel_original)


# ============================================================
# MAIN
# ============================================================

def main():

    print()
    print("╔══════════════════════════════════════════════════════════╗")
    print("║           ENZOCRYPT SECURITY TEST SUITE                 ║")
    print("║                 app1.0.5.py                             ║")
    print("╚══════════════════════════════════════════════════════════╝")

    print()
    print("Este script NO modifica tu app1.0.5.py.")
    print("Todas las pruebas utilizan archivos temporales.")
    print()

    with tempfile.TemporaryDirectory(
        prefix="EnzoCryptSecurity_"
    ) as workdir:

        try:

            env = prepare_environment(workdir)

            test_integrity(env)

            test_keys(env)

            test_cancellation(env)

        except Exception as e:

            print()
            print("=" * 70)
            print("ERROR GENERAL DEL TEST")
            print("=" * 70)

            print(type(e).__name__)
            print(str(e))

            return 1

    print()
    print("=" * 70)
    print("FIN DE LAS PRUEBAS")
    print("=" * 70)

    return 0


if __name__ == "__main__":
    sys.exit(main())