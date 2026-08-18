import os
import sys
import time
import hashlib
import tempfile
import importlib.util


# ============================================================
# CARGAR app1.0.5.py
# ============================================================

APP_FILE = os.path.join(os.path.dirname(__file__), "app1.0.5.py")

if not os.path.exists(APP_FILE):
    print("ERROR: No se encontró app1.0.5.py")
    print(f"Buscado en: {APP_FILE}")
    sys.exit(1)

spec = importlib.util.spec_from_file_location("enzocrypt", APP_FILE)
enzocrypt = importlib.util.module_from_spec(spec)
spec.loader.exec_module(enzocrypt)


# ============================================================
# CONFIGURACIÓN
# ============================================================

# Pruebas iniciales.
# 1 GB está desactivado para no hacerte esperar innecesariamente.
TESTS = [
    ("0 bytes", 0),
    ("1 byte", 1),
    ("1 MB", 1 * 1024 * 1024),
    ("8 MB", 8 * 1024 * 1024),
    ("64 MB", 64 * 1024 * 1024),
    ("65 MB", 65 * 1024 * 1024),
    ("100 MB", 100 * 1024 * 1024),
]

# Cambia a True si quieres probar 1 GB.
TEST_1GB = True

if TEST_1GB:
    TESTS.append(("1 GB", 1 * 1024 * 1024 * 1024))


# ============================================================
# UTILIDADES
# ============================================================

def format_size(size):
    if size < 1024:
        return f"{size} B"

    if size < 1024 ** 2:
        return f"{size / 1024:.2f} KB"

    if size < 1024 ** 3:
        return f"{size / (1024 ** 2):.2f} MB"

    return f"{size / (1024 ** 3):.2f} GB"


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
    Genera datos deterministas.
    No utiliza os.urandom() para que el contenido
    pueda reproducirse si necesitamos investigar un fallo.
    """

    pattern = bytes(range(256))

    with open(path, "wb") as f:
        remaining = size

        while remaining > 0:
            block_size = min(8 * 1024 * 1024, remaining)

            repeats = (block_size + len(pattern) - 1) // len(pattern)

            block = (pattern * repeats)[:block_size]

            f.write(block)

            remaining -= block_size


def progress(done, total, eta):
    if total <= 0:
        return

    percent = done / total * 100

    print(
        f"\r      Progreso: {percent:6.2f}% "
        f"| Chunk {done}/{total} "
        f"| ETA: {eta:.1f}s",
        end="",
        flush=True
    )


# ============================================================
# TEST PRINCIPAL
# ============================================================

def run_test(label, size, work_dir, public_key, private_key, password):

    print()
    print("=" * 70)
    print(f"TEST: {label}")
    print(f"Tamaño: {format_size(size)}")
    print("=" * 70)

    original = os.path.join(work_dir, "original.bin")
    encrypted = os.path.join(work_dir, "encrypted.enzocrypt")
    decrypted = os.path.join(work_dir, "decrypted.bin")

    # --------------------------------------------------------
    # 1. CREAR ARCHIVO
    # --------------------------------------------------------

    print("[1/5] Creando archivo de prueba...")

    create_test_file(original, size)

    original_size = os.path.getsize(original)

    if original_size != size:
        print("      ❌ ERROR: tamaño incorrecto")
        return False

    original_hash = sha256_file(original)

    print(f"      ✓ Archivo creado ({format_size(original_size)})")
    print(f"      SHA-256: {original_hash}")

    # --------------------------------------------------------
    # 2. CIFRAR
    # --------------------------------------------------------

    print("[2/5] Cifrando...")

    start = time.perf_counter()

    try:
        enzocrypt.encrypt_file_v2(
            original,
            public_key,
            encrypted,
            enzocrypt.CHUNK_PRESETS["Balanced (8 MB)"],
            progress_cb=progress
        )

        print()

    except Exception as e:
        print()
        print(f"      ❌ ERROR DE CIFRADO: {e}")
        return False

    encrypt_time = time.perf_counter() - start

    if not os.path.exists(encrypted):
        print("      ❌ ERROR: no se creó el archivo cifrado")
        return False

    encrypted_size = os.path.getsize(encrypted)

    print(
        f"      ✓ Cifrado correcto "
        f"({format_size(encrypted_size)})"
    )

    print(f"      Tiempo: {encrypt_time:.2f} segundos")

    # --------------------------------------------------------
    # 3. DESCIFRAR
    # --------------------------------------------------------

    print("[3/5] Descifrando...")

    start = time.perf_counter()

    try:
        enzocrypt.decrypt_file_v2(
            encrypted,
            private_key,
            password,
            decrypted,
            progress_cb=progress
        )

        print()

    except Exception as e:
        print()
        print(f"      ❌ ERROR DE DESCIFRADO: {e}")
        return False

    decrypt_time = time.perf_counter() - start

    if not os.path.exists(decrypted):
        print("      ❌ ERROR: no se creó el archivo descifrado")
        return False

    print(
        f"      ✓ Descifrado correcto "
        f"({format_size(os.path.getsize(decrypted))})"
    )

    print(f"      Tiempo: {decrypt_time:.2f} segundos")

    # --------------------------------------------------------
    # 4. COMPARAR TAMAÑOS
    # --------------------------------------------------------

    print("[4/5] Comparando tamaños...")

    decrypted_size = os.path.getsize(decrypted)

    if decrypted_size != original_size:
        print(
            f"      ❌ ERROR: tamaños diferentes\n"
            f"         Original:  {original_size}\n"
            f"         Descifrado: {decrypted_size}"
        )

        return False

    print(f"      ✓ Ambos tienen {format_size(original_size)}")

    # --------------------------------------------------------
    # 5. COMPARAR HASH
    # --------------------------------------------------------

    print("[5/5] Comparando SHA-256...")

    decrypted_hash = sha256_file(decrypted)

    print(f"      Original:  {original_hash}")
    print(f"      Descifrado: {decrypted_hash}")

    if original_hash != decrypted_hash:
        print()
        print("      ❌ ¡LOS ARCHIVOS NO COINCIDEN!")
        return False

    print("      ✓ SHA-256 coincide")
    print()
    print("      ✅ TEST SUPERADO")

    # --------------------------------------------------------
    # VELOCIDADES
    # --------------------------------------------------------

    if encrypt_time > 0:
        enc_speed = size / (1024 ** 2) / encrypt_time
    else:
        enc_speed = 0

    if decrypt_time > 0:
        dec_speed = size / (1024 ** 2) / decrypt_time
    else:
        dec_speed = 0

    print()
    print(f"      Velocidad cifrado:   {enc_speed:.2f} MB/s")
    print(f"      Velocidad descifrado: {dec_speed:.2f} MB/s")

    return True


# ============================================================
# MAIN
# ============================================================

def main():

    print()
    print("╔══════════════════════════════════════════════════════════╗")
    print("║              ENZOCRYPT V2 TEST SUITE                    ║")
    print("║              Basic File Size Tests                      ║")
    print("╚══════════════════════════════════════════════════════════╝")
    print()

    print("Aplicación:")
    print(f"  {APP_FILE}")

    print()
    print("Pruebas:")
    for name, size in TESTS:
        print(f"  • {name}")

    print()
    print("IMPORTANTE:")
    print("Los archivos de prueba se crearán en una carpeta temporal.")
    print("Al finalizar se eliminarán automáticamente.")
    print()

    # --------------------------------------------------------
    # PASSWORD DE PRUEBA
    # --------------------------------------------------------

    password = b"EnzoCrypt_Test_Password_2026!"

    # --------------------------------------------------------
    # CARPETA TEMPORAL
    # --------------------------------------------------------

    with tempfile.TemporaryDirectory(prefix="EnzoCryptTests_") as work_dir:

        print(f"Carpeta temporal:")
        print(f"  {work_dir}")
        print()

        # ----------------------------------------------------
        # GENERAR IDENTIDAD
        # ----------------------------------------------------

        print("Generando identidad RSA de prueba...")

        key_dir = os.path.join(work_dir, "keys")
        os.makedirs(key_dir)

        try:
            private_key, public_key = enzocrypt.generate_identity(
                key_dir,
                "test_identity",
                password
            )
        except Exception as e:
            print(f"❌ No se pudo generar la identidad: {e}")
            return 1

        print("✓ Claves generadas")
        print()

        # ----------------------------------------------------
        # EJECUTAR TESTS
        # ----------------------------------------------------

        results = []

        total_start = time.perf_counter()

        for label, size in TESTS:

            result = run_test(
                label,
                size,
                work_dir,
                public_key,
                private_key,
                password
            )

            results.append((label, result))

            if not result:
                print()
                print("⚠️  El test falló.")
                print("Puedes detener la batería aquí o continuar.")
                print()

        total_time = time.perf_counter() - total_start

        # ----------------------------------------------------
        # RESULTADO FINAL
        # ----------------------------------------------------

        passed = sum(1 for _, result in results if result)
        failed = len(results) - passed

        print()
        print()
        print("╔══════════════════════════════════════════════════════════╗")
        print("║                    RESULTADOS                           ║")
        print("╚══════════════════════════════════════════════════════════╝")
        print()

        for label, result in results:

            status = "PASS ✓" if result else "FAIL ✗"

            print(f"{status:8} {label}")

        print()
        print("──────────────────────────────────────────────────────────")

        print(f"Tests ejecutados : {len(results)}")
        print(f"Tests superados  : {passed}")
        print(f"Tests fallidos   : {failed}")
        print(f"Tiempo total     : {total_time:.2f} segundos")

        print()

        if failed == 0:
            print("🎉 TODOS LOS TESTS FUERON SUPERADOS")
            print()
            print("La batería básica de pruebas de tamaños")
            print("no encontró problemas en cifrado/descifrado.")
            return 0

        else:
            print("❌ HAY TESTS FALLIDOS")
            print()
            print("NO consideres esta versión lista para publicar")
            print("hasta investigar los fallos.")
            return 1


if __name__ == "__main__":
    sys.exit(main())