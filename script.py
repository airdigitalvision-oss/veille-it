```python
import os
import json
import re
import urllib.request
import feedparser
from datetime import datetime
import resend


# ============================================================
# CONFIGURATION
# ============================================================

RESEND_API_KEY = os.environ.get("RESEND_API_KEY")
EMAIL_DESTINATAIRE = os.environ.get("EMAIL_DESTINATAIRE")

if RESEND_API_KEY:
    resend.api_key = RESEND_API_KEY


# ============================================================
# SOURCES DE VEILLE INFORMATIQUE
# ============================================================
#
# IMPORTANT :
# Les sources sont séparées par domaine afin que le dashboard
# puisse filtrer correctement les actualités.
#
# Les flux institutionnels sont privilégiés pour la
# cybersécurité et les sujets réglementaires.
#
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

    clean = re.sub(r'<[^>]+>', '', texte)

    clean = re.sub(
        r'&nbsp;|&amp;|&quot;|&#39;',
        ' ',
        clean
    )

    clean = ' '.join(clean.split())

    if len(clean) > 300:
        clean = clean[:300] + "..."

    return clean


def format_date(entry):
    """
    Récupère la date publiée dans le flux.
    """

    published = (
        entry.get("published_parsed")
        or entry.get("updated_parsed")
        or entry.get("created_parsed")
    )

    if published:

        return (
            f"{published.tm_mday:02d}/"
            f"{published.tm_mon:02d}/"
            f"{published.tm_year}"
        )

    return datetime.now().strftime("%d/%m/%Y")


def nettoyer_titre(titre):
    """
    Nettoie légèrement le titre.
    """

    if not titre:
        return "Actualité informatique"

    return ' '.join(str(titre).split())


# ============================================================
# COLLECTE
# ============================================================

articles_traites = []

headers = {
    "User-Agent":
        "AirDigitalVision-Veille/1.0 "
        "(+https://airdigitalvision.fr)"
}


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
            timeout=15
        ) as response:

            xml_data = response.read()

            feed = feedparser.parse(xml_data)


        if feed.bozo:

            print(
                f"⚠️ Flux potentiellement invalide : "
                f"{feed_info['source']}"
            )


        compteur = 0


        for entry in feed.entries[:5]:

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

            date_pub = format_date(entry)


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
                    nettoyer_html(raw_desc),

                "impact_pratique":
                    (
                        f"Actualité du {date_pub} — "
                        f"Veille {feed_info['categorie']}."
                    )
            }


            articles_traites.append(article)

            compteur += 1


        print(
            f"✓ {compteur} article(s) récupéré(s)"
        )


    except Exception as e:

        print(
            f"❌ Erreur avec "
            f"{feed_info['source']} : {e}"
        )


# ============================================================
# SUPPRESSION DES DOUBLONS
# ============================================================

articles_uniques = {}

for article in articles_traites:

    cle = (
        article["titre"].strip().lower()
        + "|"
        + article["source"].strip().lower()
    )

    if cle not in articles_uniques:

        articles_uniques[cle] = article


articles_traites = list(
    articles_uniques.values()
)


# ============================================================
# TRI PAR DATE
# ============================================================

def convertir_date(date_string):

    try:

        return datetime.strptime(
            date_string,
            "%d/%m/%Y"
        )

    except:

        return datetime.min


articles_traites.sort(
    key=lambda x:
        convertir_date(x["date"]),
    reverse=True
)


# ============================================================
# FALLBACK
# ============================================================
#
# Si une source ne répond pas, on conserve une présence
# minimale de certaines catégories.
#
# Cela évite que le dashboard paraisse vide.
#
# ============================================================

categories_presentes = {
    article["categorie"]
    for article in articles_traites
}


date_jour = datetime.now().strftime(
    "%d/%m/%Y"
)


fallbacks = {

    "Cybersécurité": {

        "source": "CERT-FR / ANSSI",

        "titre":
            "Veille cybersécurité et alertes de sécurité",

        "lien":
            "https://www.cert.ssi.gouv.fr/",

        "categorie":
            "Cybersécurité",

        "resume":
            "Consultez les dernières alertes, avis de sécurité, rapports de menace et recommandations publiés par le CERT-FR.",

        "impact_pratique":
            "Surveillez régulièrement les vulnérabilités et recommandations de sécurité applicables à votre environnement informatique."
    },


    "Intelligence artificielle": {

        "source": "Air Digital Vision",

        "titre":
            "Veille Intelligence Artificielle",

        "lien":
            "https://airdigitalvision.fr/",

        "categorie":
            "Intelligence artificielle",

        "resume":
            "Suivez les évolutions des modèles d'IA, des outils génératifs, des agents IA et des usages professionnels.",

        "impact_pratique":
            "Identifier les évolutions de l'IA pouvant avoir un impact sur les usages numériques et les processus des organisations."
    },


    "Cloud & Infrastructure": {

        "source": "Air Digital Vision",

        "titre":
            "Veille Cloud & Infrastructure",

        "lien":
            "https://airdigitalvision.fr/",

        "categorie":
            "Cloud & Infrastructure",

        "resume":
            "Suivez les évolutions du cloud, des infrastructures, des conteneurs et des technologies DevOps.",

        "impact_pratique":
            "Identifier les évolutions technologiques pouvant améliorer ou modifier les infrastructures numériques."
    },


    "Open Source & Développement": {

        "source": "GitHub",

        "titre":
            "Veille Open Source & Développement",

        "lien":
            "https://github.com/",

        "categorie":
            "Open Source & Développement",

        "resume":
            "Actualités autour du développement logiciel, de l'open source et des outils destinés aux développeurs.",

        "impact_pratique":
            "Identifier les nouveaux outils, frameworks et projets open source utiles aux projets numériques."
    }
}


for categorie, fallback in fallbacks.items():

    if categorie not in categories_presentes:

        article = fallback.copy()

        article["date"] = date_jour

        articles_traites.append(article)


# ============================================================
# LIMITATION
# ============================================================

# Évite d'avoir un data.json gigantesque.
# À adapter selon tes besoins.

articles_traites = articles_traites[:100]


# ============================================================
# STATISTIQUES
# ============================================================

print(
    "\n======================================"
)

print(
    "VEILLE INFORMATIQUE"
)

print(
    "======================================"
)

print(
    f"Total : {len(articles_traites)}"
)


categories = {}

for article in articles_traites:

    categorie = article["categorie"]

    categories[categorie] = (
        categories.get(categorie, 0) + 1
    )


for categorie, nombre in categories.items():

    print(
        f"  - {categorie} : {nombre}"
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


print(
    "\n✓ data.json généré avec succès."
)


# ============================================================
# EMAIL
# ============================================================

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
                IA · Cybersécurité · Cloud · Data ·
                Open Source · Web · Technologies
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

        </div>

    """


    for art in articles_traites:

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
            f"❌ Erreur envoi mail : {e}"
        )


else:

    print(
        "\nℹ️ E-mail non envoyé : "
        "RESEND_API_KEY ou "
        "EMAIL_DESTINATAIRE absent."
    )
```
