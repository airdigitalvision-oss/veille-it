import os, json, re, time, urllib.request, urllib.parse
from datetime import datetime, timedelta, timezone
import feedparser

PERIODE_VEILLE_JOURS=21
MAX_ARTICLES_PAR_SOURCE=100
MAX_ACTUALITES_TOTAL=300
MAX_CVE_TOTAL=1000
NVD_API_URL='https://services.nvd.nist.gov/rest/json/cves/2.0'
NVD_API_KEY=os.environ.get('NVD_API_KEY')

RSS_FEEDS=[
 {'source':'CERT-FR / ANSSI','url':'https://www.cert.ssi.gouv.fr/feed/','categorie':'Cybersécurité'},
 {'source':'CERT-FR / Alertes','url':'https://www.cert.ssi.gouv.fr/alerte/feed/','categorie':'Cybersécurité'},
 {'source':'CERT-FR / Avis de sécurité','url':'https://www.cert.ssi.gouv.fr/avis/feed/','categorie':'Cybersécurité'},
 {'source':'CERT-FR / Actualités','url':'https://www.cert.ssi.gouv.fr/actualite/feed/','categorie':'Cybersécurité'},
 {'source':'NIST Cybersecurity','url':'https://www.nist.gov/news-events/cybersecurity/rss.xml','categorie':'Cybersécurité'},
 {'source':'OpenAI','url':'https://openai.com/news/rss.xml','categorie':'Intelligence artificielle'},
 {'source':'Google AI','url':'https://blog.google/technology/ai/rss/','categorie':'Intelligence artificielle'},
 {'source':'Hugging Face','url':'https://huggingface.co/blog/feed.xml','categorie':'Intelligence artificielle'},
 {'source':'Cloudflare Blog','url':'https://blog.cloudflare.com/rss/','categorie':'Cloud & Infrastructure'},
 {'source':'Kubernetes Blog','url':'https://kubernetes.io/feed.xml','categorie':'Cloud & Infrastructure'},
 {'source':'Docker Blog','url':'https://www.docker.com/feed/','categorie':'Cloud & Infrastructure'},
 {'source':'GitHub Blog','url':'https://github.blog/feed/','categorie':'Open Source & Développement'},
 {'source':'Mozilla Hacks','url':'https://hacks.mozilla.org/feed/','categorie':'Web & Technologies'},
 {'source':'Google Cloud Blog','url':'https://cloud.google.com/feeds/blog.xml','categorie':'Data'},
 {'source':'Google Developers Blog','url':'https://developers.googleblog.com/feeds/posts/default','categorie':'Web & Technologies'},
 {'source':'DMC Technologies','url':'https://dmc-technologies.fr/feed/','categorie':'Web & Technologies'},
 {'source':'ENISA','url':'https://www.enisa.europa.eu/media/news-items/news-wires/RSS','categorie':'Transformation numérique'},
]

def clean_html(x):
    if not x: return 'Consulter la source pour plus de détails.'
    x=re.sub(r'<[^>]+>',' ',str(x)); x=re.sub(r'&nbsp;',' ',x); x=re.sub(r'&amp;','&',x); x=re.sub(r'&quot;','"',x); x=re.sub(r'&#39;',"'",x)
    x=' '.join(x.split()); return x[:500]+'...' if len(x)>500 else x

def rss_date(entry):
    p=entry.get('published_parsed') or entry.get('updated_parsed') or entry.get('created_parsed')
    if not p: return None
    try: return datetime(p.tm_year,p.tm_mon,p.tm_mday,p.tm_hour,p.tm_min,p.tm_sec,tzinfo=timezone.utc)
    except Exception: return None

def iso(dt): return dt.astimezone(timezone.utc).isoformat() if dt else None

def display_date(dt): return dt.astimezone(timezone.utc).strftime('%d/%m/%Y') if dt else ''

def request_json(url,headers,retries=4):
    for i in range(retries):
        try:
            req=urllib.request.Request(url,headers=headers)
            with urllib.request.urlopen(req,timeout=45) as r: return json.loads(r.read().decode('utf-8'))
        except Exception as e:
            print(f'⚠️ Requête échouée ({i+1}/{retries}) : {e}')
            if i==retries-1: raise
            time.sleep(2**i)

def collect_news():
    out=[]; limit=datetime.now(timezone.utc)-timedelta(days=PERIODE_VEILLE_JOURS)
    for f in RSS_FEEDS:
        print('Lecture :',f['source'])
        try:
            req=urllib.request.Request(f['url'],headers={'User-Agent':'Veille-Technologique/3.0'})
            with urllib.request.urlopen(req,timeout=30) as r: feed=feedparser.parse(r.read())
            n=0
            for e in feed.entries[:MAX_ARTICLES_PAR_SOURCE]:
                dt=rss_date(e)
                if dt and dt<limit: continue
                out.append({'type':'actualite','source':f['source'],'titre':' '.join(str(e.get('title') or 'Actualité technologique').split()),'lien':e.get('link') or f['url'],'categorie':f['categorie'],'date':display_date(dt),'date_iso':iso(dt),'resume':clean_html(e.get('summary') or e.get('description') or ''),'impact_pratique':f"Actualité relevant de la catégorie {f['categorie']}."}); n+=1
            print(f'  ✓ {n} actualité(s)')
        except Exception as e: print(f'  ❌ {e}')
    d={}
    for a in out: d[(a['source'].lower(),a['titre'].lower())]=a
    out=list(d.values()); out.sort(key=lambda x:x.get('date_iso') or '',reverse=True)
    return out[:MAX_ACTUALITES_TOTAL]

def cvss(metrics):
    for key,ver in [('cvssMetricV40','4.0'),('cvssMetricV31','3.1'),('cvssMetricV30','3.0'),('cvssMetricV2','2.0')]:
        vals=metrics.get(key) or []
        if not vals: continue
        m=next((x for x in vals if x.get('type')=='Primary'),vals[0]); d=m.get('cvssData') or {}
        return d.get('baseScore'),d.get('baseSeverity') or m.get('baseSeverity') or '',ver
    return None,'',''

def collect_cves():
    out=[]; now=datetime.now(timezone.utc); start=now-timedelta(days=PERIODE_VEILLE_JOURS); idx=0
    headers={'User-Agent':'Veille-Technologique-CVE/3.0'}
    if NVD_API_KEY: headers['apiKey']=NVD_API_KEY
    while len(out)<MAX_CVE_TOTAL:
        params={'pubStartDate':start.strftime('%Y-%m-%dT%H:%M:%S.000Z'),'pubEndDate':now.strftime('%Y-%m-%dT%H:%M:%S.000Z'),'resultsPerPage':2000,'startIndex':idx}
        try: data=request_json(NVD_API_URL+'?'+urllib.parse.urlencode(params),headers)
        except Exception as e: print('❌ NVD :',e); break
        total=data.get('totalResults',0); vulns=data.get('vulnerabilities') or []
        print(f'  ✓ NVD : {idx+1}-{idx+len(vulns)} / {total}')
        for w in vulns:
            c=w.get('cve') or {}; cid=c.get('id')
            if not cid: continue
            descs=c.get('descriptions') or []; desc=next((x.get('value','') for x in descs if x.get('lang')=='en'),descs[0].get('value','') if descs else '')
            raw=c.get('published');
            try: dt=datetime.fromisoformat(raw.replace('Z','+00:00')) if raw else None
            except Exception: dt=None
            score,severity,ver=cvss(c.get('metrics') or {})
            out.append({'type':'cve','source':'NVD / NIST','titre':cid,'lien':f'https://nvd.nist.gov/vuln/detail/{cid}','categorie':'Vulnérabilités','date':display_date(dt),'date_iso':iso(dt),'resume':clean_html(desc),'impact_pratique':'Vulnérabilité publiée dans la base NVD. Vérifier les produits et versions concernés dans la fiche CVE.','cve':cid,'cvss':score,'severity':severity,'cvss_version':ver})
        if not vulns or idx+len(vulns)>=total: break
        idx+=len(vulns); time.sleep(1 if NVD_API_KEY else 6)
    d={x['cve']:x for x in out}; out=list(d.values()); out.sort(key=lambda x:x.get('date_iso') or '',reverse=True); return out[:MAX_CVE_TOTAL]

def main():
    news=collect_news(); cves=collect_cves(); data=news+cves; data.sort(key=lambda x:x.get('date_iso') or '',reverse=True)
    bad=[x for x in data if 'air digital vision' in ((str(x.get('source',''))+' '+str(x.get('lien',''))).lower())]
    if bad: raise RuntimeError('Une donnée utilise encore Air Digital Vision comme source ou lien.')
    with open('data.json','w',encoding='utf-8') as f: json.dump(data,f,ensure_ascii=False,indent=2)
    print(f'\n✓ data.json généré : {len(news)} actualités + {len(cves)} CVE = {len(data)} éléments')

if __name__=='__main__': main()
