"""
Stress test - declenche volontairement les seuils cpu/memoire/disque
----------------------------------------------------------------------
But : verifier que le dashboard/console detecte bien les anomalies
"cpu", "memoire" et "disque" definies dans monitoring_core.SEUILS et
SEUILS_WARNING, sans dependance externe (que la stdlib Python).

Usage :
    python3 stress_test.py cpu --duree 30
    python3 stress_test.py memoire --duree 30 --intensite fort
    python3 stress_test.py disque --duree 20 --dossier /tmp
    python3 stress_test.py tous --duree 30

Niveaux d'intensite :
    leger -> vise le palier WARNING (🟠) uniquement
    fort  -> vise le palier CRITIQUE (🔴)

Arrete proprement avec Ctrl+C : le nettoyage (liberer memoire, supprimer
les fichiers temporaires) se fait toujours, meme en cas d'interruption.
"""

import argparse
import multiprocessing
import os
import signal
import sys
import time

DOSSIER_TMP_DEFAUT = "/tmp/stress_test_monitoring"


# --- CPU -------------------------------------------------------------
def _boucle_cpu(duree):
    """Calcul pur, aucune I/O, pour saturer un coeur a fond pendant `duree`s."""
    fin = time.time() + duree
    x = 0.0001
    while time.time() < fin:
        x = x * x % 999999937  # calcul arbitraire, juste pour occuper le CPU


def stress_cpu(duree, intensite):
    nb_coeurs = multiprocessing.cpu_count()
    # "leger" -> ~60-70% des coeurs actifs (vise le warning 70%)
    # "fort"  -> tous les coeurs actifs (vise le critique 85%+)
    nb_process = max(1, int(nb_coeurs * (0.7 if intensite == "leger" else 1.0)))
    print(f"[cpu] {nb_process}/{nb_coeurs} coeurs sollicites pendant {duree}s ({intensite})")

    processus = [multiprocessing.Process(target=_boucle_cpu, args=(duree,)) for _ in range(nb_process)]
    for p in processus:
        p.start()
    try:
        for p in processus:
            p.join()
    except KeyboardInterrupt:
        for p in processus:
            p.terminate()
        raise


# --- Memoire -----------------------------------------------------------
def stress_memoire(duree, intensite):
    import psutil
    total = psutil.virtual_memory().total
    deja_utilise = psutil.virtual_memory().used
    # "leger" -> pousse l'usage total vers ~75% (au-dessus du warning 70%)
    # "fort"  -> pousse l'usage total vers ~90% (au-dessus du critique 85%)
    cible_pct = 0.75 if intensite == "leger" else 0.90
    a_allouer = max(0, int(total * cible_pct) - deja_utilise)
    a_allouer_mo = a_allouer // (1024 * 1024)
    print(f"[memoire] allocation de ~{a_allouer_mo} Mo pour viser {int(cible_pct*100)}% d'usage total ({intensite})")

    blocs = []
    taille_bloc = 50 * 1024 * 1024  # 50 Mo par bloc, alloue progressivement
    restant = a_allouer
    try:
        while restant > 0:
            taille = min(taille_bloc, restant)
            # bytearray reellement rempli (pas juste reserve virtuellement)
            # pour forcer le systeme a committer la memoire physique.
            blocs.append(bytearray(b"\x01" * taille))
            restant -= taille
        print(f"[memoire] cible atteinte, maintien pendant {duree}s...")
        time.sleep(duree)
    except KeyboardInterrupt:
        pass
    finally:
        print("[memoire] liberation de la memoire allouee")
        blocs.clear()


# --- Disque --------------------------------------------------------------
def stress_disque(duree, intensite, dossier):
    import psutil
    os.makedirs(dossier, exist_ok=True)
    usage = psutil.disk_usage(dossier)
    # "leger" -> pousse l'usage disque vers ~82% (au-dessus du warning 80%)
    # "fort"  -> pousse l'usage disque vers ~92% (au-dessus du critique 90%)
    cible_pct = 0.82 if intensite == "leger" else 0.92
    a_ecrire = max(0, int(usage.total * cible_pct) - usage.used)
    a_ecrire_go = a_ecrire / (1024 ** 3)
    print(f"[disque] ecriture de ~{a_ecrire_go:.2f} Go dans {dossier} pour viser "
          f"{int(cible_pct*100)}% d'usage ({intensite})")

    if a_ecrire <= 0:
        print("[disque] deja au-dessus de la cible, rien a ecrire.")
        time.sleep(duree)
        return

    taille_bloc = 100 * 1024 * 1024  # 100 Mo par fichier
    chemin_fichiers = []
    ecrit = 0
    try:
        i = 0
        while ecrit < a_ecrire:
            taille = min(taille_bloc, a_ecrire - ecrit)
            chemin = os.path.join(dossier, f"bloc_{i}.tmp")
            with open(chemin, "wb") as f:
                f.write(os.urandom(min(taille, 10 * 1024 * 1024)) * (taille // min(taille, 10 * 1024 * 1024) + 1))
            chemin_fichiers.append(chemin)
            ecrit += taille
            i += 1
        print(f"[disque] cible atteinte, maintien pendant {duree}s...")
        time.sleep(duree)
    except KeyboardInterrupt:
        pass
    finally:
        print(f"[disque] suppression des {len(chemin_fichiers)} fichiers temporaires")
        for chemin in chemin_fichiers:
            try:
                os.remove(chemin)
            except OSError:
                pass
        try:
            os.rmdir(dossier)
        except OSError:
            pass


def main():
    parser = argparse.ArgumentParser(description="Stress test cpu/memoire/disque pour tester le monitoring")
    parser.add_argument("type", choices=["cpu", "memoire", "disque", "tous"])
    parser.add_argument("--duree", type=int, default=30, help="duree du stress en secondes (defaut: 30)")
    parser.add_argument("--intensite", choices=["leger", "fort"], default="fort",
                         help="leger = vise le warning 🟠, fort = vise le critique 🔴 (defaut: fort)")
    parser.add_argument("--dossier", default=DOSSIER_TMP_DEFAUT, help="dossier temporaire pour le test disque")
    args = parser.parse_args()

    print(f"Ctrl+C pour arreter proprement a tout moment (nettoyage automatique).\n")

    try:
        if args.type in ("cpu", "tous"):
            stress_cpu(args.duree, args.intensite)
        if args.type in ("memoire", "tous"):
            stress_memoire(args.duree, args.intensite)
        if args.type in ("disque", "tous"):
            stress_disque(args.duree, args.intensite, args.dossier)
    except KeyboardInterrupt:
        print("\nInterrompu par l'utilisateur, nettoyage effectue.")
        sys.exit(0)

    print("Termine.")


if __name__ == "__main__":
    main()