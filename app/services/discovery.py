from googlesearch import search

def discover_documents(domain, limit=20):
    query = f"site:{domain} filetype:pdf"
    return list(search(query, num=limit, stop=limit, pause=2))
