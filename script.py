import os
import json
import re
import time
import urllib.request
import urllib.parse
import urllib.error
import feedparser
from datetime import datetime, timedelta, timezone

try:
    import resend
except ImportError:
    resend = None


# ============================================================
# CONFIGURATION
# ============================================================

RESEND_API_KEY = os.environ.get("RESEND_API_KEY")
EMAIL_DESTINATAIRE = os.environ.get("EMAIL_DESTINATAIRE")
NVD_API_KEY = os.environ.get("NVD_API_KEY")

if resend and RESEND_API_KEY:
    resend.api_key = RESEND_API_KEY


# ============================================================
# PARAMÈTRES DE VEILLE
# ============================================================

PERIODE_VEILLE_JOURS = 21

# Articles RSS maximum par source.
MAX_ARTICLES_PAR_SOURCE = 100

# Nombre maximum d'éléments conservés dans data.json.
# Les CVE ne sont plus limitées à 100.
MAX_ARTICLES_TOTAL = 500
MAX_CVE_TOTAL = 1000

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


# ============================================================
# SOURCES DE VEILLE
# IMPORTANT : Air Digital Vision n'est PAS une source de news.
# ============================================================

RSS_FEEDS = [
    # Cybersécurité
    {
        "source": "CERT-FR / ANSSI",
        "url": "https://www.cert.ssi.gouv.fr/feed/",
        "categorie": "Cybersécurité",
    },
    {
        "source": "CERT-FR / Alertes",
        "url": "https://www.cert.ssi.gouv.fr/alerte/feed/",
        "categorie": "Cybersécurité",
    },
    {
        "source": "CERT-FR / Avis de sécurité",
        "url": "https://www.cert.ssi.gouv.fr/avis/feed/",
        "categorie": "Vulnérabilités",
    },
    {
        "source": "CERT-FR / Actualités",
        "url": "https://www.cert.ssi.gouv.fr/actualite/feed/",
        "categorie": "Cybersécurité",
    },
    {
        "source": "NIST Cybersecurity",
        "url": "https://www.nist.gov/news-events/cybersecurity/rss.xml",
        "categorie": "Cybersécurité",
    },

    # IA
    {
        "source": "OpenAI",
        "url": "https://openai.com/news/rss.xml",
        "categorie": "Intelligence artificielle",
    },
    {
        "source": "Google AI",
        "url": "https://blog.google/technology/ai/rss/",
        "categorie": "Intelligence artificielle",
    },
    {
        "source": "Hugging Face",
        "url": "https://huggingface.co/blog/feed.xml",
        "categorie": "Intelligence artificielle",
    },

    # Cloud / infrastructure
    {
        "source": "Cloudflare Blog",
        "url": "https://blog.cloudflare.com/rss/",
        "categorie": "Cloud & Infrastructure",
    },
    {
        "source": "Kubernetes Blog",
        "url": "https://kubernetes.io/feed.xml",
        "categorie": "Cloud & Infrastructure",
    },
    {
        "source": "Docker Blog",
        "url": "https://www.docker.com/feed/",
        "categorie": "Cloud & Infrastructure",
    },

    # Open source / développement
    {
        "source": "GitHub Blog",
        "url": "https://github.blog/feed/",
        "categorie": "Open Source & Développement",
    },
    {
        "source": "Mozilla Hacks",
        "url": "https://hacks.mozilla.org/feed/",
        "categorie": "Web & Technologies",
    },

    # Data
    {
        "source": "Google Cloud Blog",
        "url": "https://cloud.google.com/feeds/blog.xml",
        "categorie": "Data",
    },

    # Web / technologies
    {
        "source": "Google Developers Blog",
        "url": "https://developers.googleblog.com/feeds/posts/default",
        "categorie": "Web & Technologies",
    },
    {
        "source": "DMC Technologies",
        "url": "https://dmc-technologies.fr/feed/",
        "categorie": "Web & Technologies",
    },

    # Transformation numérique
    {
        "source": "ENISA",
        "url": "https://www.enisa.europa.eu/media/news-items/news-wires/RSS",
        "categorie": "Transformation numérique",
    },
]


# ============================================================
# OUTILS
# ============================================================

def nettoyer_html(texte, longueur=350):
    if not texte:
        return "Consulter la source pour plus de détails."

    clean = re.sub(r"<[^>]+>", " ", str(texte))
    clean = re.sub(r"&nbsp;|&amp;|&quot;|&#39;", " ", clean)
    clean = re.sub(r"\s+", " ", clean).strip()

    if len(clean) > longueur:
        clean = clean[:longueur].rsplit(" ", 1)[0] + "..."

    return clean


def nettoyer_titre(titre):
    if not titre:
        return "Actualité informatique"
    return " ".join(str(titre).split())


def date_entry_utc(entry):
    parsed = (
        entry.get("published_parsed")
        or entry.get("updated_parsed")
        or entry.get("created_parsed")
    )

    if not parsed:
        return None

    try:
        return datetime(
            parsed.tm_year,
            parsed.tm_mon,
            parsed.tm_mday,
            parsed.tm_hour,
            parsed.tm_min,
            parsed.tm_sec,
            tzinfo=timezone.utc,
        )
    except Exception:
        return None


def format_date(date_obj):
    if not date_obj:
        return datetime.now(timezone.utc).strftime("%d/%m/%Y")
    return date_obj.strftime("%d/%m/%Y")


def iso_date(date_obj):
    if not date_obj:
        return datetime.now(timezone.utc).isoformat()
    return date_obj.isoformat()


def valeur_cvss(metrics, version):
    items = metrics.get(version, [])
    if not items:
        return None, None

    # On privilégie la métrique primaire si elle existe.
    metric = next(
        (m for m in items if m.get("type") == "Primary"),
        items[0],
    )

    data = metric.get("cvssData", {})
    return data.get("baseScore"), data.get("baseSeverity")


def extraire_cvss(cve):
    metrics = cve.get("metrics", {})

    # Priorité aux versions les plus récentes.
    for key, version in [
        ("cvssMetricV40", "4.0"),
        ("cvssMetricV31", "3.1"),
        ("cvssMetricV30", "3.0"),
        ("cvssMetricV2", "2.0"),
    ]:
        score, severity = valeur_cvss(metrics, key)
        if score is not None:
            return score, severity, version

    return None, None, None


# ============================================================
# COLLECTE RSS
# ============================================================

articles_traites = []

date_fin = datetime.now(timezone.utc)
date_limite = date_fin - timedelta(days=PERIODE_VEILLE_JOURS)

headers = {
    "User-Agent": (
        "AirDigitalVision-Veille/3.0 "
        "(+https://air-digital-vision-xua.caffeine.xyz/)"
    )
}

print("\n======================================")
print("COLLECTE DES FLUX RSS")
print("======================================")

for feed_info in RSS_FEEDS:
    print(f"\nLecture : {feed_info['source']}")

    try:
        req = urllib.request.Request(
            feed_info["url"],
            headers=headers,
        )

        with urllib.request.urlopen(req, timeout=25) as response:
            xml_data = response.read()

        feed = feedparser.parse(xml_data)

        if feed.bozo:
            print(f"⚠️ Flux potentiellement invalide : {feed_info['source']}")

        compteur = 0

        for entry in feed.entries[:MAX_ARTICLES_PAR_SOURCE]:
            date_entry = date_entry_utc(entry)

            # Si le flux fournit une date, on applique strictement les 21 jours.
            if date_entry and date_entry < date_limite:
                continue

            titre = nettoyer_titre(
                entry.get("title", "Actualité informatique")
            )

            lien = entry.get("link", feed_info["url"])

            raw_desc = entry.get(
                "summary",
                entry.get("description", ""),
            )

            article = {
                "type": "actualite",
                "source": feed_info["source"],
                "titre": titre,
                "lien": lien,
                "categorie": feed_info["categorie"],
                "date": format_date(date_entry),
                "date_iso": iso_date(date_entry),
                "resume": nettoyer_html(raw_desc),
                "impact_pratique": (
                    f"Actualité du {format_date(date_entry)} — "
                    f"veille {feed_info['categorie']}."
                ),
            }

            articles_traites.append(article)
            compteur += 1

        print(f"✓ {compteur} actualité(s) récupérée(s)")

    except Exception as e:
        print(f"❌ Erreur avec {feed_info['source']} : {e}")


# ============================================================
# COLLECTE CVE / NVD
# Pagination complète sur les résultats récents
# ============================================================

def collecter_cve_nvd():
    print("\n======================================")
    print("COLLECTE DES CVE / NVD")
    print("======================================")

    maintenant = datetime.now(timezone.utc)
    debut = maintenant - timedelta(days=PERIODE_VEILLE_JOURS)

    start_index = 0
    results_per_page = 2000
    total_cves = 0
    toutes_les_cves = []

    cve_headers = {
        "User-Agent": "AirDigitalVision-Veille/3.0",
    }

    if NVD_API_KEY:
        cve_headers["apiKey"] = NVD_API_KEY

    while total_cves < MAX_CVE_TOTAL:
        params = {
            "pubStartDate": debut.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
            "pubEndDate": maintenant.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
            "startIndex": start_index,
            "resultsPerPage": results_per_page,
        }

        url = NVD_API_URL + "?" + urllib.parse.urlencode(params)

        data = None

        for tentative in range(4):
            try:
                req = urllib.request.Request(
                    url,
                    headers=cve_headers,
                )

                with urllib.request.urlopen(req, timeout=60) as response:
                    data = json.loads(
                        response.read().decode("utf-8")
                    )

                break

            except urllib.error.HTTPError as e:
                if e.code == 429:
                    attente = 6 * (tentative + 1)
                    print(
                        f"⚠️ NVD limite de requêtes (429). "
                        f"Nouvelle tentative dans {attente}s..."
                    )
                    time.sleep(attente)
                else:
                    print(f"❌ NVD HTTP {e.code}")
                    break

            except Exception as e:
                print(f"⚠️ NVD tentative {tentative + 1}/4 : {e}")
                time.sleep(3 * (tentative + 1))

        if data is None:
            break

        vulnerabilities = data.get("vulnerabilities", [])
        total_results = data.get("totalResults", 0)

        if not vulnerabilities:
            break

        toutes_les_cves.extend(vulnerabilities)
        total_cves += len(vulnerabilities)

        print(
            f"✓ NVD : {total_cves}/{total_results} "
            f"CVE récupérées"
        )

        start_index += len(vulnerabilities)

        if start_index >= total_results:
            break

        if total_cves >= MAX_CVE_TOTAL:
            break

        # Sans clé API, on espace les appels pour respecter les limites NVD.
        if not NVD_API_KEY:
            time.sleep(6)

    compteur = 0

    for item in toutes_les_cves[:MAX_CVE_TOTAL]:
        cve = item.get("cve", {})
        cve_id = cve.get("id", "")

        if not cve_id.startswith("CVE-"):
            continue

        descriptions = cve.get("descriptions", [])
        description = ""

        for desc in descriptions:
            if desc.get("lang") == "en":
                description = desc.get("value", "")
                break

        if not description and descriptions:
            description = descriptions[0].get("value", "")

        published = cve.get("published")
        date_cve = maintenant

        if published:
            try:
                date_cve = datetime.fromisoformat(
                    published.replace("Z", "+00:00")
                ).astimezone(timezone.utc)
            except Exception:
                pass

        score, severity, version_cvss = extraire_cvss(cve)

        impact = f"CVE {cve_id} publiée récemment."

        if score is not None:
            impact = f"CVE {cve_id} — CVSS {score}"
            if version_cvss:
                impact += f" — CVSS {version_cvss}"
            if severity:
                impact += f" — {severity}"

        article = {
            "type": "cve",
            "source": "NVD / NIST",
            "titre": f"{cve_id} — Vulnérabilité de sécurité",
            "lien": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
            "categorie": "Vulnérabilités",
            "date": format_date(date_cve),
            "date_iso": iso_date(date_cve),
            "resume": nettoyer_html(description, 500),
            "impact_pratique": impact,
            "cve": cve_id,
            "cvss": score,
            "severity": severity,
            "cvss_version": version_cvss,
        }

        articles_traites.append(article)
        compteur += 1

    print(f"✓ {compteur} CVE ajoutées à la veille")


collecter_cve_nvd()


# ============================================================
# DOUBLONS
# ============================================================

articles_uniques = {}

for article in articles_traites:
    if article.get("cve"):
        cle = "cve|" + article["cve"].lower()
    else:
        cle = (
            article.get("titre", "").strip().lower()
            + "|"
            + article.get("source", "").strip().lower()
        )

    # En cas de doublon, on garde le premier élément.
    articles_uniques.setdefault(cle, article)

articles_traites = list(articles_uniques.values())


# ============================================================
# TRI
# ============================================================

articles_traites.sort(
    key=lambda x: x.get("date_iso", ""),
    reverse=True,
)

# On conserve les actualités et CVE récentes ensemble.
articles_traites = articles_traites[:MAX_ARTICLES_TOTAL]


# ============================================================
# STATISTIQUES
# ============================================================

nb_cve = sum(1 for x in articles_traites if x.get("cve"))
nb_actualites = sum(1 for x in articles_traites if not x.get("cve"))

print("\n======================================")
print("VEILLE INFORMATIQUE")
print("======================================")
print(f"Actualités : {nb_actualites}")
print(f"CVE        : {nb_cve}")
print(f"Total      : {len(articles_traites)}")
print(f"Période    : {PERIODE_VEILLE_JOURS} jours")


# ============================================================
# DATA.JSON
# ============================================================

with open("data.json", "w", encoding="utf-8") as f:
    json.dump(
        articles_traites,
        f,
        ensure_ascii=False,
        indent=2,
    )

print("✓ data.json généré avec succès.")


# ============================================================
# EMAIL
# ============================================================

if (
    articles_traites
    and resend
    and RESEND_API_KEY
    and EMAIL_DESTINATAIRE
):
    date_jour = datetime.now().strftime("%d/%m/%Y")

    html_email = f"""
    <div style="font-family:Arial,sans-serif;max-width:700px;margin:auto;color:#0f172a">
        <div style="background:#0f172a;color:white;padding:25px;border-radius:10px">
            <div style="color:#60a5fa;font-size:12px;text-transform:uppercase">
                Air Digital Vision
            </div>
            <h1>Veille Informatique & Numérique</h1>
            <p style="color:#cbd5e1">
                IA · Cybersécurité · CVE · Cloud · Data · Open Source · Web
            </p>
        </div>

        <p style="color:#64748b;font-size:13px">
            Édition du <strong>{date_jour}</strong> ·
            <strong>{nb_actualites}</strong> actualités ·
            <strong>{nb_cve}</strong> CVE ·
            {PERIODE_VEILLE_JOURS} jours d'historique
        </p>
    """

    for art in articles_traites[:100]:
        badge = ""

        if art.get("cve"):
            badge = f"""
            <div style="margin-top:8px;padding:7px 9px;
                        background:#fff7ed;border-left:3px solid #f97316;
                        font-size:12px;color:#9a3412">
                <strong>{art["cve"]}</strong>
                {" · CVSS " + str(art["cvss"]) if art.get("cvss") is not None else ""}
                {" · " + str(art["severity"]) if art.get("severity") else ""}
            </div>
            """

        html_email += f"""
        <div style="margin-bottom:15px;padding:16px;background:#f8fafc;
                    border:1px solid #e2e8f0;border-radius:6px">
            <div style="color:#64748b;font-size:11px">
                {art["date"]} · {art["categorie"]} · {art["source"]}
            </div>

            {badge}

            <h2 style="font-size:17px">
                <a href="{art["lien"]}" style="color:#0f172a;text-decoration:none">
                    {art["titre"]}
                </a>
            </h2>

            <p style="color:#475569;font-size:13px;line-height:1.5">
                {art["resume"]}
            </p>

            <div style="background:white;border-left:3px solid #2563eb;
                        padding:9px;font-size:12px;color:#475569">
                <strong>À retenir :</strong> {art["impact_pratique"]}
            </div>
        </div>
        """

    html_email += """
        <div style="border-top:1px solid #e2e8f0;padding-top:15px;
                    color:#64748b;font-size:11px;text-align:center">
            Veille automatisée par <strong>Air Digital Vision</strong><br>
            Les informations proviennent des sources originales.
        </div>
    </div>
    """

    try:
        resend.Emails.send({
            "from": "Veille Informatique <onboarding@resend.dev>",
            "to": [EMAIL_DESTINATAIRE],
            "subject": (
                f"Veille Informatique — "
                f"{nb_actualites} actualités · {nb_cve} CVE · {date_jour}"
            ),
            "html": html_email,
        })

        print("✓ E-mail envoyé avec succès.")

    except Exception as e:
        print(f"❌ Erreur envoi mail : {e}")
else:
    print(
        "ℹ️ E-mail non envoyé : "
        "RESEND_API_KEY ou EMAIL_DESTINATAIRE absent."
    )


print("\n======================================")
print("VEILLE TERMINÉE")
print("======================================")
