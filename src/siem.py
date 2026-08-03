import sys
import os

sys.path.append(os.path.dirname(__file__))

from parser import analyser_fichier
from detection import detecter_brute_force, detecter_succes_apres_echecs, detecter_spraying
from mitre import enrichir
from report import ecrire_rapport, ecrire_json


def main():
    chemin = sys.argv[1] if len(sys.argv) > 1 else "logs/auth.log"
    evenements = analyser_fichier(chemin)
    print(f"[*] {len(evenements)} evenements analyses")

    alertes = detecter_brute_force(evenements)
    alertes += detecter_succes_apres_echecs(evenements, alertes)
    alertes += detecter_spraying(evenements)
    alertes = [enrichir(a) for a in alertes]

    texte = ecrire_rapport(alertes)
    ecrire_json(alertes)
    print(texte)


if __name__ == "__main__":
    main()


