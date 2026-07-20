import re
from datetime import datetime

MOTIF_SSH = re.compile(
    r"^(?P<date>\w{3}\s+\d+\s[\d:]+)\s+"
    r"\S+\s+sshd\[\d+\]:\s+"
    r"(?P<etat>Accepted|Failed)\s+password\s+for\s+"
    r"(?P<utilisateur>\S+)\s+from\s+"
     r"(?P<ip>\d+\.\d+\.\d+\.\d+)"
)

def analyser_ligne(ligne):
    resultat = MOTIF_SSH.search(ligne)
    if resultat is None:
        return None
    donnees = resultat.groupdict()
    donnees["succes"] = donnees["etat"] == "Accepted"
    return donnees

def analyser_fichier(chemin):
    evenements = []
    with open(chemin, "r") as fichier:
        for ligne in fichier:
            donnees = analyser_ligne(ligne)
            if donnees:
                evenements.append(donnees)
    return evenements

if __name__ == "__main__":
    evenements = analyser_fichier("logs/auth.log")
    print(f"{len(evenements)} evenements analyses")
    for e in evenements[:3]:
        print(e)

