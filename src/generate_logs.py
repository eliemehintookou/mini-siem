
import random
from datetime import datetime, timedelta

IPS_NORMALES = ["192.168.1.10", "192.168.1.25", "192.168.1.42"]
IP_ATTAQUANT = "203.0.113.66"
IP_SPRAY = "198.51.100.23"
UTILISATEURS = ["elie", "admin", "root", "test", "backup"]

def ligne_log(date, ip, utilisateur, succes):
    horodatage = date.strftime("%b %d %H:%M:%S")
    etat = "Accepted" if succes else "Failed"
    return f"{horodatage} serveur sshd[1234]: {etat} password for {utilisateur} from {ip} port 22 ssh2"


def generer_logs():
    lignes = []
    maintenant = datetime.now()

    for i in range(20):
        date = maintenant - timedelta(minutes=random.randint(60, 300))
        ip = random.choice(IPS_NORMALES)
        utilisateur = random.choice(["elie", "backup"])
        lignes.append(ligne_log(date, ip, utilisateur, True))

    debut = maintenant - timedelta(minutes=30)
    for i in range(15):
        date = debut + timedelta(seconds=i * 4)
        utilisateur = random.choice(UTILISATEURS)
        lignes.append(ligne_log(date, IP_ATTAQUANT, utilisateur, False))
    lignes.append(ligne_log(debut + timedelta(seconds=70), IP_ATTAQUANT, "admin", True))

# Password spraying : 1 essai sur beaucoup de comptes, lentement
    comptes = ["admin", "root", "elie", "backup", "test", "info", "sql", "web"]
    debut_spray = maintenant - timedelta(minutes=20)
    for i, compte in enumerate(comptes):
        date = debut_spray + timedelta(minutes=i * 2)
        lignes.append(ligne_log(date, IP_SPRAY, compte, False))

    return lignes

if __name__ == "__main__":
    logs = generer_logs()
    logs.sort()
    with open("logs/auth.log", "w") as fichier:
        for ligne in logs:
            fichier.write(ligne + "\n")
    print(f"{len(logs)} lignes ecrites dans logs/auth.log")

