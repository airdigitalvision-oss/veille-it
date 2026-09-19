```python
import os
import json
import re
import urllib.request
import urllib.parse
import feedparser
from datetime import datetime, timedelta, timezone
import resend


# ============================================================
# CONFIGURATION
# ============================================================

RESEND_API_KEY = os.environ.get("RESEND_API_KEY")
EMAIL_DESTINATAIRE = os.environ.get("EMAIL_DESTINATAIRE")

if RESEND_API_KEY:
    resend.api_key = RESEND_API_KEY


# ============================================================
# PARAMÈTRES DE VEILLE
# ============================================================

# Nombre de jours d'historique
PERIODE_VEILLE_JOURS = 21

# Nombre maximum d'articles récupérés par flux RSS
MAX_ARTICLES_PAR_SOURCE = 50

# Nombre maximum de CVE récupérées depuis le NVD
MAX_CVE = 100

# Nombre maximum d'articles conservés dans data.json
MAX_ARTICLES_TOTAL = 300

# API NVD
NVD_API_URL = (
    "https://services.nvd.nist.gov/rest/json/cves/2.0"
)

# Clé API NVD optionnelle
#
# Si NVD_API_KEY est configurée dans les variables
# d'environnement, elle sera automatiquement utilisée.
NVD_API_KEY = os.environ.get("NVD_API_KEY")


# ============================================================
# SOURCES DE VEILLE INFORMATIQUE
# ============================================================

RSS_FEEDS = [

    # --------------------------------------------------------
    # CYBERSÉCURITÉ
    # --------------------------------------------------------

    {
        "source": "CERT-FR / ANSSI",
        "url": "https://www.cert.ssi.gouv.fr/feed/",
        "categorie": "Cybersécurité"
    },

    {
        "source": "CERT-FR / Alertes",
        "url": "https://www.cert.ssi.gouv.fr/alerte/feed/",
        "categorie": "Cybersécurité"
    },

    {
        "source": "CERT-FR / Avis de sécurité",
        "url": "https://www.cert.ssi.gouv.fr/avis/feed/",
        "categorie": "Vulnérabilités"
    },

    {
        "source": "CERT-FR / Actualités",
        "url": "https://www.cert.ssi.gouv.fr/actualite/feed/",
        "categorie": "Cybersécurité"
    },


    # --------------------------------------------------------
    # NIST
    # --------------------------------------------------------

    {
        "source": "NIST Cybersecurity",
        "url": "https://www.nist.gov/news-events/cybersecurity/rss.xml",
        "categorie": "Cybersécurité"
    },


    # --------------------------------------------------------
    # IA / INTELLIGENCE ARTIFICIELLE
    # --------------------------------------------------------

    {
        "source": "OpenAI",
        "url": "https://openai.com/news/rss.xml",
        "categorie": "Intelligence artificielle"
    },

    {
        "source": "Google AI",
        "url": "https://blog.google/technology/ai/rss/",
        "categorie": "Intelligence artificielle"
    },

    {
        "source": "Hugging Face",
        "url": "https://huggingface.co/blog/feed.xml",
        "categorie": "Intelligence artificielle"
    },


    # --------------------------------------------------------
    # CLOUD / INFRASTRUCTURE
    # --------------------------------------------------------

    {
        "source": "Cloudflare Blog",
        "url": "https://blog.cloudflare.com/rss/",
        "categorie": "Cloud & Infrastructure"
    },

    {
        "source": "Kubernetes Blog",
        "url": "https://kubernetes.io/feed.xml",
        "categorie": "Cloud & Infrastructure"
    },

    {
        "source": "Docker Blog",
        "url": "https://www.docker.com/feed/",
        "categorie": "Cloud & Infrastructure"
    },


    # --------------------------------------------------------
    # OPEN SOURCE / DÉVELOPPEMENT
    # --------------------------------------------------------

    {
        "source": "GitHub Blog",
        "url": "https://github.blog/feed/",
        "categorie": "Open Source & Développement"
    },

    {
        "source": "Mozilla Hacks",
        "url": "https://hacks.mozilla.org/feed/",
        "categorie": "Web & Technologies"
    },


    # --------------------------------------------------------
    # DATA
    # --------------------------------------------------------

    {
        "source": "Google Cloud Blog",
        "url": "https://cloud.google.com/feeds/blog.xml",
        "categorie": "Data"
    },


    # --------------------------------------------------------
    # WEB / TECHNOLOGIES
    # --------------------------------------------------------

    {
        "source": "Google Developers Blog",
        "url": "https://developers.googleblog.com/feeds/posts/default",
        "categorie": "Web & Technologies"
    },

    {
        "source": "DMC Technologies",
        "url": "https://dmc-technologies.fr/feed/",
        "categorie": "Web & Technologies"
    },


    # --------------------------------------------------------
    # TRANSFORMATION NUMÉRIQUE
    # --------------------------------------------------------

    {
        "source": "ENISA",
        "url": "https://www.enisa.europa.eu/media/news-items/news-wires/RSS",
        "categorie": "Transformation numérique"
    }
]


# ============================================================
# OUTILS
# ============================================================

def nettoyer_html(texte):
    """
    Supprime les balises HTML et nettoie le texte.
    """

    if not texte:
        return "Consulter la source pour plus de détails."

    clean = re.sub(
        r"<[^>]+>",
        "",
        str(texte)
    )

    clean = re.sub(
        r"&nbsp;|&amp;|&quot;|&#39;",
        " ",
        clean
    )

    clean = " ".join(clean.split())

    if len(clean) > 300:
        clean = clean[:300] + "..."

    return clean


def nettoyer_titre(titre):
    """
    Nettoie légèrement le titre.
    """

    if not titre:
        return "Actualité informatique"

    return " ".join(
        str(titre).split()
    )


def obtenir_date_entry(entry):
    """
    Récupère la date d'une entrée RSS.
    """

    published = (
        entry.get("published_parsed")
        or entry.get("updated_parsed")
        or entry.get("created_parsed")
    )

    if published:

        try:

            return datetime(
                published.tm_year,
                published.tm_mon,
                published.tm_mday,
                published.tm_hour,
                published.tm_min,
                published.tm_sec
            )

        except Exception:
            pass

    return None


def format_date_datetime(date_obj):
    """
    Transforme un datetime en DD/MM/YYYY.
    """

    if date_obj:

        return date_obj.strftime(
            "%d/%m/%Y"
        )

    return datetime.now().strftime(
        "%d/%m/%Y"
    )


def convertir_date(date_string):
    """
    Transforme DD/MM/YYYY en datetime
    pour permettre le tri.
    """

    try:

        return datetime.strptime(
            date_string,
            "%d/%m/%Y"
        )

    except Exception:

        return datetime.min


# ============================================================
# COLLECTE RSS
# ============================================================

articles_traites = []

date_limite = (
    datetime.now()
    - timedelta(
        days=PERIODE_VEILLE_JOURS
    )
)


headers = {
    "User-Agent":
        "Veille-Informatique/2.0"
}


print("")
print("======================================")
print("COLLECTE DES FLUX RSS")
print("======================================")


for feed_info in RSS_FEEDS:

    print(
        f"\nLecture de : "
        f"{feed_info['source']}"
    )

    try:

        req = urllib.request.Request(
            feed_info["url"],
            headers=headers
        )

        with urllib.request.urlopen(
            req,
            timeout=20
        ) as response:

            xml_data = response.read()

        feed = feedparser.parse(
            xml_data
        )

        if feed.bozo:

            print(
                f"⚠️ Flux potentiellement "
                f"invalide : "
                f"{feed_info['source']}"
            )

        compteur = 0

        for entry in feed.entries[
            :MAX_ARTICLES_PAR_SOURCE
        ]:

            date_entry = obtenir_date_entry(
                entry
            )

            # ------------------------------------------------
            # FILTRE 21 JOURS
            # ------------------------------------------------

            if (
                date_entry
                and date_entry < date_limite
            ):

                continue

            titre = nettoyer_titre(
                entry.get(
                    "title",
                    "Actualité informatique"
                )
            )

            lien = entry.get(
                "link",
                feed_info["url"]
            )

            raw_desc = entry.get(
                "summary",
                entry.get(
                    "description",
                    ""
                )
            )

            date_pub = format_date_datetime(
                date_entry
            )

            article = {

                "source":
                    feed_info["source"],

                "titre":
                    titre,

                "lien":
                    lien,

                "categorie":
                    feed_info["categorie"],

                "date":
                    date_pub,

                "resume":
                    nettoyer_html(
                        raw_desc
                    ),

                "impact_pratique":
                    (
                        f"Actualité du "
                        f"{date_pub} — "
                        f"Veille "
                        f"{feed_info['categorie']}."
                    )
            }

            articles_traites.append(
                article
            )

            compteur += 1

        print(
            f"✓ {compteur} article(s) "
            f"récupéré(s)"
        )

    except Exception as e:

        print(
            f"❌ Erreur avec "
            f"{feed_info['source']} : "
            f"{e}"
        )


# ============================================================
# COLLECTE CVE / NVD
# ============================================================

def collecter_cve_nvd():

    print("")
    print("======================================")
    print("COLLECTE DES CVE / NVD")
    print("======================================")

    try:

        maintenant = datetime.now(
            timezone.utc
        )

        debut = (
            maintenant
            - timedelta(
                days=PERIODE_VEILLE_JOURS
            )
        )

        params = {

            "pubStartDate":
                debut.strftime(
                    "%Y-%m-%dT%H:%M:%S.000"
                ),

            "pubEndDate":
                maintenant.strftime(
                    "%Y-%m-%dT%H:%M:%S.000"
                ),

            "resultsPerPage":
                MAX_CVE
        }

        url = (
            NVD_API_URL
            + "?"
            + urllib.parse.urlencode(
                params
            )
        )

        cve_headers = {

            "User-Agent":
                "Veille-Informatique/2.0"
        }

        if NVD_API_KEY:

            cve_headers[
                "apiKey"
            ] = NVD_API_KEY

        req = urllib.request.Request(
            url,
            headers=cve_headers
        )

        with urllib.request.urlopen(
            req,
            timeout=30
        ) as response:

            data = json.loads(
                response.read().decode(
                    "utf-8"
                )
            )

        vulnerabilities = data.get(
            "vulnerabilities",
            []
        )

        print(
            f"✓ {len(vulnerabilities)} "
            f"CVE reçues du NVD"
        )

        compteur = 0

        for item in vulnerabilities:

            cve = item.get(
                "cve",
                {}
            )

            cve_id = cve.get(
                "id",
                ""
            )

            if not cve_id.startswith(
                "CVE-"
            ):

                continue

            # ------------------------------------------------
            # DESCRIPTION
            # ------------------------------------------------

            descriptions = cve.get(
                "descriptions",
                []
            )

            description = ""

            # Priorité à l'anglais
            for desc in descriptions:

                if (
                    desc.get("lang")
                    == "en"
                ):

                    description = desc.get(
                        "value",
                        ""
                    )

                    break

            if (
                not description
                and descriptions
            ):

                description = (
                    descriptions[0]
                    .get(
                        "value",
                        ""
                    )
                )

            # ------------------------------------------------
            # DATE
            # ------------------------------------------------

            published = cve.get(
                "published"
            )

            date_cve = datetime.now()

            if published:

                try:

                    date_cve = (
                        datetime.fromisoformat(
                            published.replace(
                                "Z",
                                "+00:00"
                            )
                        )
                        .replace(
                            tzinfo=None
                        )
                    )

                except Exception:
                    pass

            # ------------------------------------------------
            # CVSS
            # ------------------------------------------------

            score = None
            severity = None
            version_cvss = None

            metrics = cve.get(
                "metrics",
                {}
            )

            # ------------------------------------------------
            # CVSS V4
            # ------------------------------------------------

            if metrics.get(
                "cvssMetricV40"
            ):

                metric = metrics[
                    "cvssMetricV40"
                ][0]

                cvss_data = metric.get(
                    "cvssData",
                    {}
                )

                score = cvss_data.get(
                    "baseScore"
                )

                severity = cvss_data.get(
                    "baseSeverity"
                )

                version_cvss = "4.0"

            # ------------------------------------------------
            # CVSS V3.1
            # ------------------------------------------------

            elif metrics.get(
                "cvssMetricV31"
            ):

                metric = metrics[
                    "cvssMetricV31"
                ][0]

                cvss_data = metric.get(
                    "cvssData",
                    {}
                )

                score = cvss_data.get(
                    "baseScore"
                )

                severity = cvss_data.get(
                    "baseSeverity"
                )

                version_cvss = "3.1"

            # ------------------------------------------------
            # CVSS V3.0
            # ------------------------------------------------

            elif metrics.get(
                "cvssMetricV30"
            ):

                metric = metrics[
                    "cvssMetricV30"
                ][0]

                cvss_data = metric.get(
                    "cvssData",
                    {}
                )

                score = cvss_data.get(
                    "baseScore"
                )

                severity = cvss_data.get(
                    "baseSeverity"
                )

                version_cvss = "3.0"

            # ------------------------------------------------
            # RÉSUMÉ
            # ------------------------------------------------

            resume = nettoyer_html(
                description
            )

            # ------------------------------------------------
            # IMPACT
            # ------------------------------------------------

            if score is not None:

                impact = (
                    f"CVE {cve_id} — "
                    f"CVSS {score}"
                )

                if version_cvss:

                    impact += (
                        f" — CVSS "
                        f"{version_cvss}"
                    )

                if severity:

                    impact += (
                        f" — {severity}"
                    )

            else:

                impact = (
                    f"CVE {cve_id} "
                    f"publiée récemment."
                )

            # ------------------------------------------------
            # ARTICLE
            # ------------------------------------------------

            article = {

                "source":
                    "NVD / NIST",

                "titre":
                    (
                        f"{cve_id} — "
                        f"Vulnérabilité "
                        f"de sécurité"
                    ),

                "lien":
                    (
                        "https://nvd.nist.gov/"
                        f"vuln/detail/{cve_id}"
                    ),

                "categorie":
                    "Vulnérabilités",

                "date":
                    date_cve.strftime(
                        "%d/%m/%Y"
                    ),

                "resume":
                    resume,

                "impact_pratique":
                    impact,

                "cve":
                    cve_id,

                "cvss":
                    score,

                "severity":
                    severity,

                "cvss_version":
                    version_cvss
            }

            articles_traites.append(
                article
            )

            compteur += 1

        print(
            f"✓ {compteur} CVE "
            f"ajoutées à la veille"
        )

    except Exception as e:

        print(
            f"❌ Erreur NVD/CVE : "
            f"{e}"
        )


collecter_cve_nvd()


# ============================================================
# SUPPRESSION DES DOUBLONS
# ============================================================

print("")
print("======================================")
print("SUPPRESSION DES DOUBLONS")
print("======================================")


articles_uniques = {}


for article in articles_traites:

    # Pour les CVE, l'identifiant CVE
    # est utilisé comme clé principale.
    if article.get("cve"):

        cle = (
            "cve|"
            + article["cve"].lower()
        )

    else:

        cle = (
            article["titre"]
            .strip()
            .lower()
            + "|"
            + article["source"]
            .strip()
            .lower()
        )

    if cle not in articles_uniques:

        articles_uniques[
            cle
        ] = article


articles_traites = list(
    articles_uniques.values()
)


print(
    f"✓ {len(articles_traites)} "
    f"articles uniques"
)


# ============================================================
# TRI PAR DATE
# ============================================================

articles_traites.sort(
    key=lambda x:
        convertir_date(
            x["date"]
        ),
    reverse=True
)


# ============================================================
# LIMITATION
# ============================================================

articles_traites = articles_traites[
    :MAX_ARTICLES_TOTAL
]


# ============================================================
# STATISTIQUES
# ============================================================

print("")
print("======================================")
print("VEILLE INFORMATIQUE")
print("======================================")


print(
    f"Total : "
    f"{len(articles_traites)}"
)


categories = {}


for article in articles_traites:

    categorie = article[
        "categorie"
    ]

    categories[categorie] = (
        categories.get(
            categorie,
            0
        ) + 1
    )


for categorie, nombre in categories.items():

    print(
        f"  - {categorie} : "
        f"{nombre}"
    )


# ============================================================
# ENREGISTREMENT DATA.JSON
# ============================================================

with open(
    "data.json",
    "w",
    encoding="utf-8"
) as f:

    json.dump(
        articles_traites,
        f,
        ensure_ascii=False,
        indent=2
    )


print("")
print(
    "✓ data.json généré avec succès."
)


# ============================================================
# EMAIL
# ============================================================

date_jour = datetime.now().strftime(
    "%d/%m/%Y"
)


if (
    articles_traites
    and RESEND_API_KEY
    and EMAIL_DESTINATAIRE
):

    html_email = f"""

    <div style="
        font-family: Arial, Helvetica, sans-serif;
        max-width: 700px;
        margin: auto;
        color: #0f172a;
    ">

        <div style="
            background:#0f172a;
            color:white;
            padding:25px;
            border-radius:10px;
        ">

            <div style="
                color:#60a5fa;
                font-size:12px;
                text-transform:uppercase;
                letter-spacing:1px;
            ">
                Air Digital Vision
            </div>

            <h1 style="
                margin:8px 0;
                font-size:25px;
            ">
                Veille Informatique & Numérique
            </h1>

            <p style="
                color:#cbd5e1;
                font-size:13px;
                margin:0;
            ">
                IA · Cybersécurité · CVE · Cloud ·
                Data · Open Source · Web · Technologies
            </p>

        </div>

        <div style="
            padding:15px 0;
            color:#64748b;
            font-size:13px;
        ">

            Édition du

            <strong>
                {date_jour}
            </strong>

            ·

            <strong>
                {len(articles_traites)}
            </strong>

            actualités

            ·

            <strong>
                {PERIODE_VEILLE_JOURS}
            </strong>

            jours d'historique

        </div>

    """

    for art in articles_traites:

        # ----------------------------------------------------
        # Informations CVE
        # ----------------------------------------------------

        cve_badge = ""

        if art.get("cve"):

            severity = (
                art.get("severity")
                or ""
            )

            score = art.get(
                "cvss"
            )

            cvss_text = ""

            if score is not None:

                cvss_text = (
                    f" · CVSS {score}"
                )

            cve_badge = f"""

            <div style="
                margin-top:8px;
                padding:7px 9px;
                background:#fff7ed;
                border-left:3px solid #f97316;
                font-size:12px;
                color:#9a3412;
            ">

                <strong>
                    {art.get("cve")}
                </strong>

                {cvss_text}

                {f" · {severity}" if severity else ""}

            </div>

            """

        html_email += f"""

        <div style="
            margin-bottom:15px;
            padding:16px;
            background:#f8fafc;
            border:1px solid #e2e8f0;
            border-left:4px solid #2563eb;
            border-radius:6px;
        ">

            <div style="
                color:#64748b;
                font-size:11px;
                margin-bottom:6px;
            ">

                {art['date']}

                ·

                <strong>
                    {art['categorie']}
                </strong>

                ·

                {art['source']}

            </div>

            <h2 style="
                font-size:17px;
                margin:5px 0 8px;
            ">

                <a
                    href="{art['lien']}"
                    style="
                        color:#0f172a;
                        text-decoration:none;
                    "
                >

                    {art['titre']}

                </a>

            </h2>

            {cve_badge}

            <p style="
                color:#475569;
                font-size:13px;
                line-height:1.5;
            ">

                {art['resume']}

            </p>

            <div style="
                background:#ffffff;
                border-left:3px solid #2563eb;
                padding:9px;
                font-size:12px;
                color:#475569;
            ">

                <strong>
                    À retenir :
                </strong>

                {art['impact_pratique']}

            </div>

            <p style="
                margin-top:12px;
            ">

                <a
                    href="{art['lien']}"
                    style="
                        color:#2563eb;
                        font-size:12px;
                        font-weight:bold;
                    "
                >

                    Consulter la source →

                </a>

            </p>

        </div>

        """

    html_email += """

        <div style="
            margin-top:20px;
            padding-top:15px;
            border-top:1px solid #e2e8f0;
            color:#64748b;
            font-size:11px;
            text-align:center;
        ">

            Veille automatisée par

            <strong>
                Air Digital Vision
            </strong>

            <br>

            Période analysée :
            21 derniers jours

            <br>

            Les informations proviennent
            des sources originales.

            <br>

            Consultez toujours la source originale
            pour obtenir l'information complète.

        </div>

    </div>

    """

    try:

        resend.Emails.send({

            "from":
                "Veille Informatique <onboarding@resend.dev>",

            "to":
                [EMAIL_DESTINATAIRE],

            "subject":
                (
                    f"Veille Informatique & Numérique "
                    f"— {len(articles_traites)} actualités "
                    f"— {date_jour}"
                ),

            "html":
                html_email
        })

        print(
            "✓ E-mail envoyé avec succès !"
        )

    except Exception as e:

        print(
            f"❌ Erreur envoi mail : "
            f"{e}"
        )

else:

    print(
        "\nℹ️ E-mail non envoyé : "
        "RESEND_API_KEY ou "
        "EMAIL_DESTINATAIRE absent."
    )


# ============================================================
# FIN
# ============================================================

print("")
print("======================================")
print("VEILLE TERMINÉE")
print("======================================")
print(
    f"Période : "
    f"{PERIODE_VEILLE_JOURS} jours"
)
print(
    f"Articles : "
    f"{len(articles_traites)}"
)
print("======================================")
```
