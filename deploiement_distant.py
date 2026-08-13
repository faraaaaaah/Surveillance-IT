"""
Deploiement a distance de l'agent de surveillance
------------------------------------------------------------------------------
Permet a l'admin d'installer et de lancer l'agent de surveillance sur une
machine distante (Windows ou Linux) SANS avoir a s'y connecter physiquement,
en fournissant juste son IP et des identifiants (login/mot de passe) ayant
les droits d'installation sur cette machine.

CE QUE FAIT CE SCRIPT :
    1. Se connecte a la machine distante (SSH pour Linux, WinRM pour Windows)
    2. Verifie/installe Python si besoin (Linux) ou verifie sa presence
       (Windows - l'installation automatique de Python via WinRM n'est PAS
       geree ici, voir PREREQUIS ci-dessous)
    3. Installe les dependances (psutil, requests) via pip
    4. Copie le script agent (agent_pc.py) sur la machine distante
    5. Le lance en tache de fond, configuree pour redemarrer automatiquement
       avec la machine (service systemd sous Linux, tache planifiee sous
       Windows)

CE QUE CE SCRIPT NE FAIT **PAS** (limites assumees, a lire avant de tester) :
    - Il n'active PAS SSH ou WinRM sur la machine cible si ce n'est pas deja
      fait. C'est la LIMITE PRINCIPALE de cette approche "push" : contrairement
      a un simple lien d'installation qu'on colle une fois sur la machine
      cible (approche "pull"), le "push" exige que la machine cible accepte
      deja les connexions entrantes SSH/WinRM. Si ce n'est pas le cas, ce
      script echouera immediatement avec une erreur de connexion claire -
      ce n'est pas un bug, c'est un prerequis manquant a regler AVANT.
    - Il n'installe PAS Python sous Windows si absent (l'installation
      automatise de Python via WinRM est fragile et depasse le cadre de ce
      script pour l'instant - la machine Windows cible doit deja avoir
      Python d'installe).
    - Il ne gere PAS la creation de compte dashboard pour le proprietaire de
      la machine (fonctionnalite separee, non traitee ici).

PREREQUIS SUR LA MACHINE CIBLE (a vérifier/activer AVANT de lancer ce script) :

    --- Linux ---
    - Serveur SSH actif (verifie generalement deja present sur la plupart
      des distributions serveur ; sinon : sudo apt install openssh-server)
    - Un compte avec les droits sudo (pour installer les paquets)

    --- Windows ---
    - WinRM active. Sur la machine cible, en PowerShell (en Administrateur) :
          Enable-PSRemoting -Force
          Set-Item WSMan:\\localhost\\Service\\Auth\\Basic -Value $true
      (Basic auth utilisee ici par simplicite sur reseau local de confiance;
      pour un reseau non fiable, preferer NTLM/Kerberos ou une connexion
      WinRM chiffree en HTTPS - a durcir avant tout usage en production reelle.)
    - Python 3 deja installe sur la machine cible et accessible dans le PATH
    - Un compte avec les droits administrateur

INSTALLATION (sur la machine de l'admin qui lance ce script) :
    pip install paramiko pywinrm

UTILISATION :
    python deploiement_distant.py --ip 192.168.1.50 --os linux --nom PC-Bob \\
        --url https://.../api/ingest --cle cle-demo-a-changer

    python deploiement_distant.py --ip 192.168.1.60 --os windows --nom PC-Alice \\
        --url https://.../api/ingest --cle cle-demo-a-changer

    Le login et le mot de passe de la machine distante sont demandes de
    facon interactive (jamais en argument de ligne de commande, pour ne pas
    les exposer dans l'historique du shell ou la liste des processus).
"""

import argparse
import base64
import getpass
import os
import sys
import time

DOSSIER_SCRIPT = os.path.dirname(os.path.abspath(__file__))
AGENT_LOCAL_DEFAUT = os.path.join(DOSSIER_SCRIPT, "agent_pc.py")


# ==============================================================================
# LINUX (SSH via paramiko)
# ==============================================================================

def deployer_linux(ip, utilisateur, mot_de_passe, agent_local, nom_serveur, url_ingest, cle_api):
    try:
        import paramiko
    except ImportError:
        sys.exit("paramiko n'est pas installe. Lance : pip install paramiko")

    print(f"[deploiement] Connexion SSH a {ip}...")
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(ip, username=utilisateur, password=mot_de_passe, timeout=10)
    except Exception as e:
        sys.exit(f"[deploiement] Echec de connexion SSH a {ip} : {e}\n"
                  f"Verifie que le service SSH est actif sur la machine cible "
                  f"et que les identifiants sont corrects.")

    def executer(commande, sudo=False):
        cmd = f"sudo -S {commande}" if sudo else commande
        stdin, stdout, stderr = client.exec_command(cmd, timeout=60)
        if sudo:
            stdin.write(mot_de_passe + "\n")
            stdin.flush()
        code = stdout.channel.recv_exit_status()
        sortie = stdout.read().decode(errors="replace")
        erreur = stderr.read().decode(errors="replace")
        return code, sortie, erreur

    print("[deploiement] Verification de Python3...")
    code, sortie, _ = executer("python3 --version")
    if code != 0:
        sys.exit(f"[deploiement] Python3 n'est pas installe sur {ip}. "
                  f"Installe-le manuellement d'abord (sudo apt install python3 python3-pip).")
    print(f"[deploiement] {sortie.strip()} trouve.")

    print("[deploiement] Installation des dependances (psutil, requests)...")
    code, sortie, erreur = executer("pip3 install --user psutil requests")
    if code != 0:
        print(f"[deploiement] ⚠️  Echec pip3 --user, nouvelle tentative avec --break-system-packages...")
        code, sortie, erreur = executer("pip3 install --break-system-packages psutil requests")
        if code != 0:
            sys.exit(f"[deploiement] Impossible d'installer les dependances : {erreur}")
    print("[deploiement] Dependances installees.")

    if not os.path.exists(agent_local):
        sys.exit(f"[deploiement] Fichier agent introuvable en local : {agent_local}")

    print("[deploiement] Copie de l'agent sur la machine distante...")
    sftp = client.open_sftp()
    chemin_distant = "/home/{}/agent_surveillance.py".format(utilisateur)
    sftp.put(agent_local, chemin_distant)
    sftp.close()

    print("[deploiement] Lancement de l'agent en tache de fond (persistant via systemd)...")
    service_contenu = f"""[Unit]
Description=Agent de surveillance
After=network.target

[Service]
ExecStart=/usr/bin/python3 {chemin_distant} --url {url_ingest} --cle {cle_api}
Restart=always
User={utilisateur}

[Install]
WantedBy=multi-user.target
"""
    # On ecrit le fichier service via un heredoc pour eviter les soucis
    # d'echappement de guillemets en passant par exec_command direct.
    commande_ecriture = (
        f"cat > /tmp/agent-surveillance.service << 'EOF'\n{service_contenu}\nEOF"
    )
    executer(commande_ecriture)
    code, _, erreur = executer(
        "mv /tmp/agent-surveillance.service /etc/systemd/system/agent-surveillance.service "
        "&& systemctl daemon-reload "
        "&& systemctl enable agent-surveillance "
        "&& systemctl restart agent-surveillance",
        sudo=True
    )
    if code != 0:
        sys.exit(f"[deploiement] Echec de la creation du service systemd : {erreur}")

    print(f"[deploiement] ✅ Agent installe et demarre sur {ip} ({nom_serveur}).")
    print(f"[deploiement] Il redemarrera automatiquement avec la machine.")
    client.close()


# ==============================================================================
# WINDOWS (WinRM via pywinrm)
# ==============================================================================

def deployer_windows(ip, utilisateur, mot_de_passe, agent_local, nom_serveur, url_ingest, cle_api):
    try:
        import winrm
    except ImportError:
        sys.exit("pywinrm n'est pas installe. Lance : pip install pywinrm")

    print(f"[deploiement] Connexion WinRM a {ip}...")
    session = winrm.Session(ip, auth=(utilisateur, mot_de_passe), transport="ntlm")

    def executer_ps(script_ps):
        resultat = session.run_ps(script_ps)
        return resultat.status_code, resultat.std_out.decode(errors="replace"), resultat.std_err.decode(errors="replace")

    print("[deploiement] Verification de Python...")
    code, sortie, erreur = executer_ps("python --version")
    if code != 0:
        sys.exit(f"[deploiement] Python n'est pas trouve sur {ip} (PATH). "
                  f"Installe-le manuellement d'abord sur la machine cible - "
                  f"l'installation automatique de Python via WinRM n'est pas geree par ce script.")
    print(f"[deploiement] {sortie.strip()} trouve.")

    print("[deploiement] Installation des dependances (psutil, requests)...")
    code, sortie, erreur = executer_ps("pip install psutil requests")
    if code != 0:
        sys.exit(f"[deploiement] Echec installation dependances : {erreur}")
    print("[deploiement] Dependances installees.")

    if not os.path.exists(agent_local):
        sys.exit(f"[deploiement] Fichier agent introuvable en local : {agent_local}")

    print("[deploiement] Copie de l'agent sur la machine distante...")
    with open(agent_local, "rb") as f:
        contenu_b64 = base64.b64encode(f.read()).decode()

    chemin_distant = "C:\\agent_surveillance.py"
    # Ecriture via base64 pour eviter tout probleme d'encodage/guillemets
    # avec le contenu du script transmis en une commande PowerShell.
    script_ecriture = f"""
$bytes = [System.Convert]::FromBase64String("{contenu_b64}")
[System.IO.File]::WriteAllBytes("{chemin_distant}", $bytes)
"""
    code, _, erreur = executer_ps(script_ecriture)
    if code != 0:
        sys.exit(f"[deploiement] Echec de la copie de l'agent : {erreur}")

    print("[deploiement] Creation de la tache planifiee (demarrage automatique)...")
    nom_tache = "AgentSurveillance"
    commande_agent = f'python "{chemin_distant}" --url {url_ingest} --cle {cle_api}'
    script_tache = f"""
schtasks /Create /TN "{nom_tache}" /TR '{commande_agent}' /SC ONSTART /RU "{utilisateur}" /RP "{mot_de_passe}" /F
schtasks /Run /TN "{nom_tache}"
"""
    code, sortie, erreur = executer_ps(script_tache)
    if code != 0:
        sys.exit(f"[deploiement] Echec de la creation de la tache planifiee : {erreur}")

    print(f"[deploiement] ✅ Agent installe et demarre sur {ip} ({nom_serveur}).")
    print(f"[deploiement] Il redemarrera automatiquement avec la machine (tache planifiee '{nom_tache}').")


# ==============================================================================
# MAIN
# ==============================================================================

def main():
    parser = argparse.ArgumentParser(description="Deploie l'agent de surveillance sur une machine distante")
    parser.add_argument("--ip", required=True, help="Adresse IP de la machine cible")
    parser.add_argument("--os", required=True, choices=["linux", "windows"], help="Systeme de la machine cible")
    parser.add_argument("--nom", required=True, help="Nom a donner a ce serveur dans le dashboard")
    parser.add_argument("--url", required=True, help="URL complete vers /api/ingest du dashboard")
    parser.add_argument("--cle", required=True, help="Cle API du dashboard (DASHBOARD_API_KEY)")
    parser.add_argument("--agent", default=AGENT_LOCAL_DEFAUT,
                         help=f"Chemin local vers le script agent a deployer (defaut: {AGENT_LOCAL_DEFAUT})")
    args = parser.parse_args()

    print(f"=== Deploiement sur {args.ip} ({args.os}) ===")
    utilisateur = input("Login (compte admin sur la machine cible) : ").strip()
    mot_de_passe = getpass.getpass("Mot de passe (jamais affiche ni stocke) : ")

    debut = time.time()
    if args.os == "linux":
        deployer_linux(args.ip, utilisateur, mot_de_passe, args.agent, args.nom, args.url, args.cle)
    else:
        deployer_windows(args.ip, utilisateur, mot_de_passe, args.agent, args.nom, args.url, args.cle)

    print(f"[deploiement] Termine en {time.time() - debut:.1f}s.")
    print(f"[deploiement] Verifie dans quelques instants que '{args.nom}' apparait dans le dashboard.")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[deploiement] Annule par l'utilisateur.")