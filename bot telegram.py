import logging
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import Application, CommandHandler, MessageHandler, filters
import dns.resolver
from whois import whois
import requests
import shodan

# Configuration
TOKEN = "7848590213:AAG3DDeuHdrdwL4ogxdV4eFpbCjfYtr14qI"
SHODAN_KEY = "406d8c7c6fe244c083aded1770d0f8d1"  # Clé API Shodan

# Configuration du système de logging
logging.basicConfig(
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    level=logging.INFO
)

async def start(update: Update, context):
    """
    Gère la commande /start et affiche le menu principal avec les options de scan.
    """
    keyboard = [
        [InlineKeyboardButton("🌐 Scan Domaine", callback_data='domain')],
        [InlineKeyboardButton("📡 Scan IP", callback_data='ip')],
        [InlineKeyboardButton("📧 Scan Email", callback_data='email')]
    ]
    await update.message.reply_text(
        "🕷️ *Spider Intel - Scanner OSINT*\nChoisissez un type de scan ou envoyez directement :\n• google.com\n• 8.8.8.8\n• exemple@domaine.com",
        reply_markup=InlineKeyboardMarkup(keyboard),
        parse_mode='Markdown'
    )

async def handle_message(update: Update, context):
    """
    Gère les messages entrants et détermine automatiquement le type de scan à effectuer.
    """
    text = update.message.text.strip()
    
    if not text:
        await update.message.reply_text("❌ Veuillez entrer une cible valide")
        return
    
    try:
        # Détection automatique du type de scan
        if "@" in text:  # Si le texte contient @, c'est un email
            await scan_email(update, text)
        elif text.replace(".", "").isdigit():  # Si c'est numérique, c'est une IP
            await scan_ip(update, text)
        elif "." in text:  # Si contient un point, c'est un domaine
            await scan_domain(update, text)
        else:
            await update.message.reply_text("❌ Type de cible non reconnu. Utilisez un domaine, IP ou email.")
            
    except Exception as e:
        logging.error(f"Erreur: {str(e)}")
        await update.message.reply_text(f"⚠️ Erreur: {str(e)}")

async def scan_domain(update: Update, domain: str):
    """
    Effectue un scan complet d'un domaine avec WHOIS, DNS et vérification HTTP.
    """
    try:
        # Nettoyage de l'input
        domain = domain.lower().replace("https://", "").replace("http://", "").split("/")[0]
        
        # Récupération des informations WHOIS
        domain_info = whois(domain)
        creation_date = domain_info.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        
        # Résolution DNS
        resolver = dns.resolver.Resolver()
        resolver.timeout = 3
        ns_records = [str(r) for r in resolver.resolve(domain, 'NS')]
        
        # Vérification HTTP
        response = requests.get(f"https://{domain}", timeout=5)
        server_header = response.headers.get('Server', 'Inconnu')
        
        # Construction et envoi du résultat
        await update.message.reply_text(
            f"🔍 *Domaine:* {domain}\n\n"
            f"• 📅 Créé le: {creation_date}\n"
            f"• 🌍 Registrar: {domain_info.registrar or 'Inconnu'}\n"
            f"• 🛡️ Serveurs DNS:\n   - {ns_records[0]}\n   - {ns_records[1] if len(ns_records) > 1 else ''}\n"
            f"• 🌐 Serveur: {server_header}\n"
            f"• 🔗 HTTPS: {'✅' if response.status_code == 200 else '❌'}",
            parse_mode='Markdown'
        )
        
    except Exception as e:
        await update.message.reply_text(f"❌ Erreur domaine: {str(e)}")

async def scan_ip(update: Update, ip: str):
    """
    Effectue un scan d'une adresse IP en utilisant l'API Shodan.
    """
    try:
        api = shodan.Shodan(SHODAN_KEY)
        result = api.host(ip)
        
        # Extraction des informations pertinentes
        org = result.get('org', 'Inconnu')
        isp = result.get('isp', 'Inconnu')
        ports = ", ".join(str(p) for p in result['ports'])
        
        # Construction et envoi du résultat
        await update.message.reply_text(
            f"📡 *IP:* {ip}\n\n"
            f"• 🏢 Organisation: {org}\n"
            f"• 📶 ISP: {isp}\n"
            f"• 🌍 Localisation: {result.get('country_name', 'Inconnu')}\n"
            f"• 🚪 Ports ouverts: {ports}\n"
            f"• ⚠️ Vulnérabilités: {len(result.get('vulns', []))}",
            parse_mode='Markdown'
        )
        
    except shodan.APIError as e:
        await update.message.reply_text(f"❌ Erreur Shodan: {str(e)}")
    except Exception as e:
        await update.message.reply_text(f"⚠️ Erreur IP: {str(e)}")

async def scan_email(update: Update, email: str):
    """
    Effectue une analyse basique d'une adresse email.
    """
    try:
        # Vérification basique de la syntaxe
        if "@" not in email or "." not in email.split("@")[1]:
            raise ValueError("Format d'email invalide")
            
        domain = email.split("@")[1]
        
        # Vérification MX
        try:
            mx_records = dns.resolver.resolve(domain, 'MX')
            mx_servers = [str(r.exchange) for r in mx_records]
            mx_status = "✅"
        except:
            mx_servers = []
            mx_status = "❌"
        
        # Construction et envoi du résultat
        response = (
            f"📧 *Email:* {email}\n\n"
            f"• 🌐 Domaine: {domain}\n"
            f"• 📨 Serveurs MX: {mx_status}\n"
        )
        
        if mx_servers:
            response += "   - " + "\n   - ".join(mx_servers) + "\n"
        
        await update.message.reply_text(response, parse_mode='Markdown')
        
    except Exception as e:
        await update.message.reply_text(f"⚠️ Erreur email: {str(e)}")

def main():
    """
    Fonction principale qui initialise et lance le bot.
    """
    # Création de l'application Telegram
    app = Application.builder().token(TOKEN).build()
    
    # Ajout des handlers
    app.add_handler(CommandHandler("start", start))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_message))
    
    # Démarrage du bot
    logging.info("Bot démarré")
    app.run_polling()

if __name__ == "__main__":
    main()