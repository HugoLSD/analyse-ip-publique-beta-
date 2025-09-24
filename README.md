# Analyse IP Publique - Script Bash

Ce script permet d'analyser une IP publique dans un réseau de manière sécurisée et ludique, en automatisant plusieurs étapes comme le whois, traceroute, scans nmap, vérifications de ports et recherches Shodan/VirusTotal.

## 📦 Prérequis

* Kali Linux (ou tout autre Linux compatible)
* Commandes suivantes installées :

  * `whois`
  * `traceroute`
  * `nmap`
  * `curl`
  * `jq` (optionnel, pour afficher proprement les JSON Shodan/VirusTotal)
* (Optionnel) Clés API pour Shodan et VirusTotal : (le propose automatiquement pendant le script)

  * `SHODAN_API_KEY`
  * `VT_API_KEY`

## ⚙️ Installation

1. Téléchargez le script `analyse_ip_public.sh` et placez-le dans un répertoire de votre choix, par exemple :

```bash
mkdir -p ~/scripts
mv analyse_ip_public.sh ~/scripts/
```

2. Rendez le script exécutable :

```bash
chmod +x ~/scripts/analyse_ip_public.sh
```

3. (Optionnel) Exportez vos clés API si vous souhaitez activer Shodan et VirusTotal :

```bash
export SHODAN_API_KEY="votre_cle_shodan"
export VT_API_KEY="votre_cle_virustotal"
```

## 🚀 Utilisation

Exécutez le script avec une IP publique en paramètre :

```bash
sudo ~/scripts/analyse_ip_public.sh <IP>
```

* Exemple :

```bash
sudo ~/scripts/analyse_ip_public.sh 8.8.8.8
```

### 📝 Que fait le script ?

1. **whois** : récupère les informations sur le propriétaire de l'IP.
2. **traceroute** : visualise le chemin parcouru par les paquets jusqu'à l'IP (UDP et ICMP).
3. **nmap top 1000** : scan rapide des ports les plus courants avec détection de services et OS.
4. **nmap full scan** : scan complet sur tous les ports (0-65535).
5. **Test ports communs** : vérifie rapidement l'ouverture de ports populaires (22, 80, 443, etc.).
6. **Shodan** : recherche publique des services exposés sur l'IP (nécessite clé API).
7. **VirusTotal** : vérifie la réputation de l'IP (nécessite clé API).
8. **Vérification IP privée/publique** : indique si l'IP appartient à une plage privée.

## 📂 Résultats

Tous les résultats sont sauvegardés dans un dossier horodaté du type :

```
ip_analysis_YYYYMMDD_HHMMSS_<IP>
```

Le script affiche également un récapitulatif rapide des fichiers créés.

## ⚠️ Sécurité et légalité

* N'effectuez ces scans que sur des IP ou machines que vous êtes autorisé à tester.
* Le scan d'IP externes sans autorisation peut être considéré comme une intrusion et être illégal.

## 🎉 Amusez-vous bien !

Le script est conçu pour être pédagogique et ludique, avec des emojis et des explications étape par étape pour comprendre chaque action entreprise.
