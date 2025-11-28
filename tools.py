import vt
from langchain_tavily import TavilySearch
from langchain_community.agent_toolkits import GmailToolkit
from langchain_community.tools.gmail.utils import get_gmail_credentials, build_resource_service
from langchain.tools import tool
from config import config
from datetime import datetime

#USAMOS LA CLASE PARA VALIDAR LA CONFIGURACIÓN
config.validate_required_config()

#1 TAVILYSEARCH - HERRAMIENTA PRE-CONSTRUIDA - HERRAMIENTA PARA HACER BÚSQUEDAS POS INTERNET
search_tool = TavilySearch(
    max_results = 3,
    api_key = config.TAVILY_API_KEY
)

#2 GMAILTOOLS - HERRAMIENTA PRE-CONSTRUIDA
creds = get_gmail_credentials(
    token_file=config.GMAIL_TOKEN_FILE,
    client_secrets_file=config.GMAIL_CREDENTIALS_FILE,
    scopes = ["https://mail.google.com/"]
)

gmail_toolkit = GmailToolkit(api_resource=build_resource_service(credentials=creds))
gmail_tools = gmail_toolkit.get_tools()

#3 VIRUSTOTAL TOOL
@tool
def virustotal_checker(indicator: str, indicator_type: str) -> str:
    """ANALIZA URLS, IPS Y HASHES USANDO LA API DE VIRUS TOTAL
    
    ARG:
        INDICATOR: URL, IP O HASH A ANALIZAR
        INDICATOR_TYPE: 'URL', 'IP' O 'HASH'
    
    RETURNS:
        RESULTADO DEL ANALISIS DE VIRUSTOTAL
    """

    try:
        with vt.Client(config.VIRUSTOTAL_API_KEY) as client:
            if indicator_type == "url":
                url_id = vt.url_id(indicator)
                analysis = client.get_object(f"/urls/{url_id}")
            elif indicator_type == "ip":
                analysis = client.get_object(f"/ip-addresses/{indicator}")
            elif indicator_type == "hash":
                analysis = client.get_object(f"/files/{indicator}")
            else:
                return f"Tipo no soportado: {indicator_type}"
            
            stats = analysis.last_analysis_stats
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            total = sum(stats.values())

            if malicious > 5:
                threat_level = "MALICIOSO"
            elif malicious > 0 or suspicious > 3:
                threat_level = "SOSPECHOSO"
            else:
                threat_level = "LIMPIO"

            return f"""ANALISIS VIRUSTOTAL:
Indicador: {indicator}
Detecciones: {malicious}/{total} maliciosas, {suspicious}/{total} sospechosas
Clasificacion: {threat_level}
Análisis: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"""
    
    except Exception as e:
        return f"Error VirusTotal: {str(e)}"
    
# Lista de herramientas para importacion
all_tools = [search_tool, virustotal_checker] + gmail_tools