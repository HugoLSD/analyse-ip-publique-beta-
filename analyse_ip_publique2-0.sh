#!/usr/bin/env bash
# analyse_ip_public_ameliore.sh
# Version améliorée et interactive du script d'analyse IP publique
# Ajoute : saisie interactive des clés API, vérification root, résumé synthétique, test HTTP/HTTPS

set -o pipefail

# --- Entrée de l'utilisateur ---
read -p "Entrez l'IP publique à analyser : " IP
if [[ -z "$IP" ]]; then
  echo "[⚠️] Aucune IP fournie, sortie du script."
  exit 1
fi

# --- Vérification droits root ---
if [[ $EUID -ne 0 ]]; then
  echo "[⚠️] Certaines fonctionnalités (traceroute UDP, nmap SYN scan) nécessitent sudo."
  echo "Essayez de relancer le script avec sudo si certains scans échouent."
fi

# --- Saisie interactive des clés API ---
if [[ -z "$SHODAN_API_KEY" ]]; then
  read -p "Entrez votre clé API Shodan (laissez vide pour ignorer) : " SHODAN_API_KEY
fi
if [[ -z "$VT_API_KEY" ]]; then
  read -p "Entrez votre clé API VirusTotal (laissez vide pour ignorer) : " VT_API_KEY
fi

OUTDIR="ip_analysis_$(date +%Y%m%d_%H%M%S)_${IP//:/_}"
mkdir -p "$OUTDIR"

echo "[🎯] Analyse de l'IP : $IP"
echo "[🗂️] Résultats sauvegardés dans : $OUTDIR"

# --- Fonction pour afficher étape ---
function etape() {
  echo -e "\n---- $1 ----"
  echo "$2"
}

# --- 1) Whois ---
etape "1) whois" "Découvrir le propriétaire de l'IP"
whois "$IP" | tee "$OUTDIR/whois.txt"

# --- 2) Traceroute ---
etape "2) traceroute" "Visualiser le chemin des paquets"
if command -v traceroute >/dev/null 2>&1; then
  if [[ $EUID -eq 0 ]]; then
    echo "[🛣️] Traceroute UDP..."
    traceroute -U -w 2 -q 1 "$IP" 2>&1 | tee "$OUTDIR/traceroute.txt"
  else
    echo "[⚠️] Traceroute UDP ignoré (pas de droits root)" | tee "$OUTDIR/traceroute.txt"
  fi
  echo "[🛣️] Traceroute ICMP..."
  traceroute -I -w 2 -q 1 "$IP" 2>&1 | tee -a "$OUTDIR/traceroute.txt"
else
  echo "[⚠️] traceroute non installé" | tee "$OUTDIR/traceroute.txt"
fi

# --- 3) Nmap top 1000 ---
etape "3) nmap top 1000" "Scan rapide des ports les plus courants"
if command -v nmap >/dev/null 2>&1; then
  nmap -Pn --top-ports 1000 -sS -sV -O --reason -oN "$OUTDIR/nmap_top1000.txt" "$IP" || true
else
  echo "[⚠️] nmap non installé" | tee "$OUTDIR/nmap_top1000.txt"
fi

# --- 4) Nmap full scan ---
etape "4) nmap full scan" "Scan complet sur tous les ports (0-65535)"
if command -v nmap >/dev/null 2>&1; then
  nmap -Pn -p- -sS -sV --min-rate 500 --reason -oN "$OUTDIR/nmap_fullports.txt" "$IP" || true
else
  echo "[⚠️] nmap non installé" | tee "$OUTDIR/nmap_fullports.txt"
fi

# --- 5) Test rapide ports communs ---
etape "5) Test ports communs" "Vérification rapide de ports populaires"
COMMON_PORTS=(22 80 443 3389 21 25 53 123 5060 5900 8080)
> "$OUTDIR/port_check.txt"
for p in "${COMMON_PORTS[@]}"; do
  timeout 3 bash -c "</dev/tcp/$IP/$p" 2>/dev/null && echo "port $p ouvert" || echo "port $p fermé/filtré" >> "$OUTDIR/port_check.txt"
done

# --- 6) Test HTTP/HTTPS ---
etape "6) Test HTTP/HTTPS" "Vérification connectivité web"
for port in 80 443; do
  if curl -Is --connect-timeout 3 "$IP:$port" >/dev/null 2>&1; then
    echo "Port $port répond" >> "$OUTDIR/http_test.txt"
  else
    echo "Port $port ne répond pas" >> "$OUTDIR/http_test.txt"
  fi
done

# --- 7) Shodan ---
etape "7) Shodan" "Recherche publique (clé API nécessaire)"
if [[ -n "$SHODAN_API_KEY" ]]; then
  curl -s "https://api.shodan.io/shodan/host/$IP?key=$SHODAN_API_KEY" -o "$OUTDIR/shodan.json" || true
else
  echo "SHODAN_API_KEY non fourni" > "$OUTDIR/shodan.txt"
fi

# --- 8) VirusTotal ---
etape "8) VirusTotal" "Vérification réputation IP"
if [[ -n "$VT_API_KEY" ]]; then
  curl -s -H "x-apikey: $VT_API_KEY" "https://www.virustotal.com/api/v3/ip_addresses/$IP" -o "$OUTDIR/virustotal.json" || true
else
  echo "VT_API_KEY non fourni" > "$OUTDIR/virustotal.txt"
fi

# --- 9) Vérification IP privée/public ---
etape "9) Vérification IP privée/public" "Détecte si IP est dans plage privée"
if [[ "$IP" =~ ^10\.|^192\.168\.|^172\.(1[6-9]|2[0-9]|3[0-1])\. ]]; then
  echo "$IP semble être une IP privée" > "$OUTDIR/ip_type.txt"
else
  echo "$IP semble être une IP publique" > "$OUTDIR/ip_type.txt"
fi

# --- 10) Résumé synthétique ---
echo -e "\n---- RÉCAPITULATIF SYNTHÉTIQUE ----"
echo "Résultats enregistrés dans $OUTDIR"
ls -lh "$OUTDIR"

echo "⚠️ Note : N'effectue ces actions que sur des cibles autorisées."
echo "🎉 Script terminé."
