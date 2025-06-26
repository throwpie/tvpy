from flask import Flask, request, Response
import requests
from urllib.parse import urlparse, urljoin, quote, unquote
import re
import traceback
import json
import base64
from urllib.parse import quote_plus
import os
import random
import time
from cachetools import TTLCache, LRUCache
from dotenv import load_dotenv

app = Flask(__name__)

load_dotenv()

# --- General Configuration ---
# Allows you to disable SSL certificate verification.
# Set the VERIFY_SSL environment variable to "False" or "0" to disable.
# WARNING: Disabling SSL verification may expose you to security risks (e.g. man-in-the-middle attacks).
# Only use this option if you are aware of the risks or if you need to operate behind an SSL-inspecting proxy.
VERIFY_SSL = os.environ.get('VERIFY_SSL', 'false').lower() not in ('false', '0', 'no')
if not VERIFY_SSL:
    print("WARNING: SSL certificate verification is DISABLED. This may expose you to security risks.")
    # Suppress unsafe request warnings only if verification is disabled
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# HTTP request timeout in seconds.
# Can be overridden with the REQUEST_TIMEOUT environment variable.
REQUEST_TIMEOUT = int(os.environ.get('REQUEST_TIMEOUT', 15))
print(f"Request timeout set to {REQUEST_TIMEOUT} seconds.")

# --- Proxy Configuration ---
PROXY_LIST = []

def setup_proxies():
    #Loads the list of SOCKS5, HTTP and HTTPS proxies from environment variables.
    global PROXY_LIST
    proxies_found = []

    # Load SOCKS5 proxy (supports comma separated list)
    socks_proxy_list_str = os.environ.get('SOCKS5_PROXY')
    if socks_proxy_list_str:
        raw_socks_list = [p.strip() for p in socks_proxy_list_str.split(',') if p.strip()]
        if raw_socks_list:
            print(f"Trovati {len(raw_socks_list)} SOCKS5 proxies found. They will be used in rotation.")
            for proxy in raw_socks_list:
                # Automatically recognizes and converts to socks5h for remote DNS resolution
                final_proxy_url = proxy
                if proxy.startswith('socks5://'):
                    final_proxy_url = 'socks5h' + proxy[len('socks5'):]
                    print(f"SOCKS5 proxy converted to ensure remote DNS resolution")
                elif not proxy.startswith('socks5h://'):
                    print(f"WARNING: The SOCKS5 proxy URL is not a valid SOCKS5 format (e.g. socks5:// or socks5h://). This may not work.")
                proxies_found.append(final_proxy_url)
            print("Make sure you have installed the SOCKS dependency: 'pip install PySocks'")

    # HTTP Proxy
    http_proxy_list_str = os.environ.get('HTTP_PROXY')
    if http_proxy_list_str:
        http_proxies = [p.strip() for p in http_proxy_list_str.split(',') if p.strip()]
        if http_proxies:
            print(f"Found {len(http_proxies)} HTTP proxies. They will be used on a rotating basis.")
            proxies_found.extend(http_proxies)

    # HTTPS Proxy
    https_proxy_list_str = os.environ.get('HTTPS_PROXY')
    if https_proxy_list_str:
        https_proxies = [p.strip() for p in https_proxy_list_str.split(',') if p.strip()]
        if https_proxies:
            print(f"Found {len(https_proxies)} HTTPS proxies. They will be used on a rotating basis.")
            # Use extend to add all proxies from the list
            proxies_found.extend(https_proxies)

    PROXY_LIST = proxies_found

    if PROXY_LIST:
        print(f"Total of {len(PROXY_LIST)} proxies configured. They will be used on a rotating basis for each request.")
    else:
        print("No proxy (SOCKS5, HTTP, HTTPS) configured.")

def get_proxy_for_url(url):
    #Selects a random proxy from the list, but skips it for GitHub domains.
    #Returns the formatted proxy dictionary for the requests library, or None.
    
    if not PROXY_LIST:
        return None

    # Check if the URL is a GitHub domain to skip the proxy
    try:
        parsed_url = urlparse(url)
        if 'github.com' in parsed_url.netloc:
            print(f"Request to Github detected ({url}), proxy will be skipped.")
            return None
    except Exception:
        # If the URL is invalid, proceed anyway (it could be a fragment)
        pass

    chosen_proxy = random.choice(PROXY_LIST)
    return {'http': chosen_proxy, 'https': chosen_proxy}

setup_proxies()

# --- Cache Configuration ---
M3U8_CACHE = TTLCache(maxsize=200, ttl=5)
TS_CACHE = LRUCache(maxsize=1000)
KEY_CACHE = LRUCache(maxsize=200)

# --- Dynamic DaddyLive URL Fetcher ---
DADDYLIVE_BASE_URL = None
LAST_FETCH_TIME = 0
FETCH_INTERVAL = 3600  # 1 hour in seconds

def get_daddylive_base_url():
    """Fetches and caches the dynamic base URL for DaddyLive."""
    global DADDYLIVE_BASE_URL, LAST_FETCH_TIME
    current_time = time.time()
    
    # Return cached URL if it's not expired
    if DADDYLIVE_BASE_URL and (current_time - LAST_FETCH_TIME < FETCH_INTERVAL):
        return DADDYLIVE_BASE_URL

    try:
        print("Fetching dynamic DaddyLive base URL from GitHub...")
        github_url = 'https://raw.githubusercontent.com/thecrewwh/dl_url/refs/heads/main/dl.xml'
        response = requests.get(
            github_url,
            timeout=REQUEST_TIMEOUT,
            proxies=get_proxy_for_url(github_url),
            verify=VERIFY_SSL
        )
        response.raise_for_status()
        content = response.text
        match = re.search(r'src\s*=\s*"([^"]*)"', content)
        if match:
            base_url = match.group(1)
            if not base_url.endswith('/'):
                base_url += '/'
            DADDYLIVE_BASE_URL = base_url
            LAST_FETCH_TIME = current_time
            print(f"Dynamic DaddyLive base URL updated to: {DADDYLIVE_BASE_URL}")
            return DADDYLIVE_BASE_URL
    except requests.RequestException as e:
        print(f"Error fetching dynamic DaddyLive URL: {e}. Using fallback.")
    
    # Fallback in case of any error
    DADDYLIVE_BASE_URL = "https://daddylive.sx/"
    print(f"Using fallback DaddyLive URL: {DADDYLIVE_BASE_URL}")
    return DADDYLIVE_BASE_URL

get_daddylive_base_url()  # Fetch on startup

def detect_m3u_type(content):
    # Detect if it is a M3U (IPTV list) or a M3U8 (HLS stream)
    if "#EXTM3U" in content and "#EXTINF" in content:
        return "m3u8"
    return "m3u"

def replace_key_uri(line, headers_query):
    # Replace AES-128 key URI with proxy
    match = re.search(r'URI="([^"]+)"', line)
    if match:
        key_url = match.group(1)
        proxied_key_url = f"/proxy/key?url={quote(key_url)}&{headers_query}"
        return line.replace(key_url, proxied_key_url)
    return line

def extract_channel_id(url):
    # Extract channel ID from various URL formats

    # Pattern for /premium.../mono.m3u8
    match_premium = re.search(r'/premium(\d+)/mono\.m3u8$', url)
    if match_premium:
        return match_premium.group(1)

    # Unified pattern for /watch/, /stream/, /cast/, /player/
    # Example: /watch/stream-12345.php
    match_player = re.search(r'/(?:watch|stream|cast|player)/stream-(\d+)\.php', url)
    if match_player:
        return match_player.group(1)

    return None

def process_daddylive_url(url):
    # Convert old URLs to DaddyLive 2025 compatible formats
    daddy_base_url = get_daddylive_base_url()
    daddy_domain = urlparse(daddy_base_url).netloc

    # Convert premium URLs to watch format
    match_premium = re.search(r'/premium(\d+)/mono\.m3u8$', url)
    if match_premium:
        channel_id = match_premium.group(1)
        new_url = f"{daddy_base_url}watch/stream-{channel_id}.php"
        print(f"URL processed from {url} to {new_url}")
        return new_url

    # If it's already a modern DaddyLive URL (with watch, stream, cast, player), use it directly
    if daddy_domain in url and any(p in url for p in ['/watch/', '/stream/', '/cast/', '/player/']):
        return url

    # If it contains only numbers, create watch URL
    if url.isdigit():
        return f"{daddy_base_url}watch/stream-{url}.php"

    return url

def resolve_m3u8_link(url, headers=None):

    # Resolve DaddyLive URL. If the URL is not for DaddyLive,
    # It simply cleans up the embedded headers and returns it.
    if not url:
        print("Error: URL not provided.")
        return {"resolved_url": None, "headers": {}}

    # Make a copy of the headers to avoid modifying the original
    current_headers = headers.copy() if headers else {}
    
    # Extracting embedded headers from URL
    clean_url = url
    extracted_headers = {}
    if '&h_' in url or '%26h_' in url:
        print("Header parameters detected in URL - Extracting...")
        temp_url = url
        # Special handling for vavoo which sometimes uses %26 instead of &
        if 'vavoo.to' in temp_url.lower() and '%26' in temp_url:
             temp_url = temp_url.replace('%26', '&')
        
        # Generic handling for double-encoded URLs
        if '%26h_' in temp_url:
            temp_url = unquote(unquote(temp_url))

        url_parts = temp_url.split('&h_', 1)
        clean_url = url_parts[0]
        header_params = '&h_' + url_parts[1]
        
        for param in header_params.split('&'):
            if param.startswith('h_'):
                try:
                    key_value = param[2:].split('=', 1)
                    if len(key_value) == 2:
                        key = unquote(key_value[0]).replace('_', '-')
                        value = unquote(key_value[1])
                        extracted_headers[key] = value
                except Exception as e:
                    print(f"Error extracting header {param}: {e}")

    # --- Start DaddyLive specific resolution logic ---
    print(f"Attempting URL resolution (DaddyLive): {clean_url}")

    daddy_base_url = get_daddylive_base_url()
    daddy_origin = urlparse(daddy_base_url).scheme + "://" + urlparse(daddy_base_url).netloc

    # DaddyLive Resolution Specific Headers
    daddylive_headers = {
        'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36',
        'Referer': daddy_base_url,
        'Origin': daddy_origin
    }
    # Let's merge the headers: daddylive's take precedence for resolution
    final_headers_for_resolving = {**current_headers, **daddylive_headers}

    try:
        # Get dynamic base URL
        print("Getting dynamic base URL...")
        github_url = 'https://raw.githubusercontent.com/thecrewwh/dl_url/refs/heads/main/dl.xml'
        main_url_req = requests.get(
            github_url,
            timeout=REQUEST_TIMEOUT,
            proxies=get_proxy_for_url(github_url),
            verify=VERIFY_SSL
        )
        main_url_req.raise_for_status()
        main_url = main_url_req.text
        baseurl = re.findall('src = "([^"]*)', main_url)[0]
        print(f"Base URL obtained: {baseurl}")

        # Extract channel ID from clean URL
        channel_id = extract_channel_id(clean_url)
        if not channel_id:
            print(f"Failed to extract channel ID from {clean_url}")
            # Fallback: Returns the clean URL
            return {"resolved_url": clean_url, "headers": current_headers}

        print(f"Extracted channel ID: {channel_id}")

        # Build stream URL (same as addon.py)
        stream_url = f"{baseurl}stream/stream-{channel_id}.php"
        print(f"Constructed stream URL: {stream_url}")

        # Update header with correct baseurl
        final_headers_for_resolving['Referer'] = baseurl + '/'
        final_headers_for_resolving['Origin'] = baseurl

        # STEP 1: Query the stream page to find Player 2
        print(f"Passo 1: Richiesta a {stream_url}")
        response = requests.get(stream_url, headers=final_headers_for_resolving, timeout=REQUEST_TIMEOUT, proxies=get_proxy_for_url(stream_url), verify=VERIFY_SSL)
        response.raise_for_status()

        # Search Player 2 link (exact method from addon.py)
        iframes = re.findall(r'<a[^>]*href="([^"]+)"[^>]*>\s*<button[^>]*>\s*Player\s*2\s*<\/button>', response.text)
        if not iframes:
            print("No Player 2 links found")
            return {"resolved_url": clean_url, "headers": current_headers}

        print(f"Step 2: Found Player 2 link: {iframes[0]}")

        # STEP 2: Follow the link Player 2
        url2 = iframes[0]
        url2 = baseurl + url2
        url2 = url2.replace('//cast', '/cast')  # Fix from addon.py

        # Update header
        final_headers_for_resolving['Referer'] = url2
        final_headers_for_resolving['Origin'] = url2

        print(f"Step 3: Request to Player 2: {url2}")
        response = requests.get(url2, headers=final_headers_for_resolving, timeout=REQUEST_TIMEOUT, proxies=get_proxy_for_url(url2), verify=VERIFY_SSL)
        response.raise_for_status()

        # STEP 3: Search for iframe in Player 2 response
        iframes = re.findall(r'iframe src="([^"]*)', response.text)
        if not iframes:
            print("No iframe found on Player 2 page")
            return {"resolved_url": clean_url, "headers": current_headers}

        iframe_url = iframes[0]
        print(f"Step 4: Found iframe: {iframe_url}")

        # STEP 4: Access the iframe
        print(f"Step 5: Request iframe: {iframe_url}")
        response = requests.get(iframe_url, headers=final_headers_for_resolving, timeout=REQUEST_TIMEOUT, proxies=get_proxy_for_url(iframe_url), verify=VERIFY_SSL)
        response.raise_for_status()

        iframe_content = response.text

        # STEP 5: Extract parameters from iframe (exact method addon.py)
        try:
            channel_key = re.findall(r'(?s) channelKey = \"([^"]*)', iframe_content)[0]

            # Extract and decode base64 parameters
            auth_ts_b64 = re.findall(r'(?s)c = atob\("([^"]*)', iframe_content)[0]
            auth_ts = base64.b64decode(auth_ts_b64).decode('utf-8')

            auth_rnd_b64 = re.findall(r'(?s)d = atob\("([^"]*)', iframe_content)[0]
            auth_rnd = base64.b64decode(auth_rnd_b64).decode('utf-8')

            auth_sig_b64 = re.findall(r'(?s)e = atob\("([^"]*)', iframe_content)[0]
            auth_sig = base64.b64decode(auth_sig_b64).decode('utf-8')
            auth_sig = quote_plus(auth_sig)

            auth_host_b64 = re.findall(r'(?s)a = atob\("([^"]*)', iframe_content)[0]
            auth_host = base64.b64decode(auth_host_b64).decode('utf-8')

            auth_php_b64 = re.findall(r'(?s)b = atob\("([^"]*)', iframe_content)[0]
            auth_php = base64.b64decode(auth_php_b64).decode('utf-8')

            print(f"Parametri estratti: channel_key={channel_key}")

        except (IndexError, Exception) as e:
            print(f"Errore estrazione parametri: {e}")
            return {"resolved_url": clean_url, "headers": current_headers}

        # STEP 6: Authentication Request
        auth_url = f'{auth_host}{auth_php}?channel_id={channel_key}&ts={auth_ts}&rnd={auth_rnd}&sig={auth_sig}'
        print(f"Step 6: Authentication: {auth_url}")

        auth_response = requests.get(auth_url, headers=final_headers_for_resolving, timeout=REQUEST_TIMEOUT, proxies=get_proxy_for_url(auth_url), verify=VERIFY_SSL)
        auth_response.raise_for_status()

        # STEP 7: Extract host and server lookup
        host = re.findall('(?s)m3u8 =.*?:.*?:.*?".*?".*?"([^"]*)', iframe_content)[0]
        server_lookup = re.findall(r'n fetchWithRetry\(\s*\'([^\']*)', iframe_content)[0]

        # STEP 8: Server lookup to get server_key
        server_lookup_url = f"https://{urlparse(iframe_url).netloc}{server_lookup}{channel_key}"
        print(f"Step 7: Server lookup: {server_lookup_url}")

        lookup_response = requests.get(server_lookup_url, headers=final_headers_for_resolving, timeout=REQUEST_TIMEOUT, proxies=get_proxy_for_url(server_lookup_url), verify=VERIFY_SSL)
        lookup_response.raise_for_status()
        server_data = lookup_response.json()
        server_key = server_data['server_key']

        print(f"Server key obtained: {server_key}")

        # STEP 9: Build final M3U8 URL WITHOUT proxy parameters
        referer_raw = f'https://{urlparse(iframe_url).netloc}'

        # CLEAN M3U8 base URL (without proxy parameters)
        clean_m3u8_url = f'https://{server_key}{host}{server_key}/{channel_key}/mono.m3u8'

        print(f"Clean M3U8 URL built: {clean_m3u8_url}")

        # Header corretti per il fetch
        final_headers_for_fetch = {
            'User-Agent': final_headers_for_resolving.get('User-Agent'),
            'Referer': referer_raw,
            'Origin': referer_raw
        }

        return {
            "resolved_url": clean_m3u8_url,  # CLEAN URL without proxy parameters
            "headers": final_headers_for_fetch # Header corrected
        }

    except (requests.exceptions.ConnectTimeout, requests.exceptions.ProxyError) as e:
        print(f"TIMEOUT OR PROXY ERROR WHILE RESOLVING: {e}")
        print("This problem is often related to a slow, broken, or blocked SOCKS5 proxy.")
        print("TIPS: Check that your proxies are active. Try increasing the timeout by setting the environment variable 'REQUEST_TIMEOUT' (e.g. to 20 or 30 seconds).")
        return {"resolved_url": clean_url, "headers": current_headers}
    except Exception as e:
        print(f"Error while resolving: {e}")
        import traceback
        print(f"Traceback: {traceback.format_exc()}")
        # Fallback: restituisce l'URL pulito originale
        return {"resolved_url": clean_url, "headers": current_headers}

@app.route('/proxy/m3u')
def proxy_m3u():
    # Proxy for M3U and M3U8 files with DaddyLive 2025 support and caching
    m3u_url = request.args.get('url', '').strip()
    if not m3u_url:
        return "Error: Missing 'url' parameter", 400

    # Create a unique cache key based on the URL and headers
    cache_key_headers = "&".join(sorted([f"{k}={v}" for k, v in request.args.items() if k.lower().startswith("h_")]))
    cache_key = f"{m3u_url}|{cache_key_headers}"

    # Check if the response is already in cache
    if cache_key in M3U8_CACHE:
        print(f"HIT cache for M3U8: {m3u_url}")
        cached_response = M3U8_CACHE[cache_key]
        return Response(cached_response, content_type="application/vnd.apple.mpegurl")
    print(f"MISS cache for M3U8: {m3u_url}")

    daddy_base_url = get_daddylive_base_url()
    daddy_origin = urlparse(daddy_base_url).scheme + "://" + urlparse(daddy_base_url).netloc

    # Default headers updated for DaddyLive 2025
    default_headers = {
        "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36",
        "Referer": daddy_base_url,
        "Origin": daddy_origin
    }

    # Extract headers from request, overriding defaults
    request_headers = {
        unquote(key[2:]).replace("_", "-"): unquote(value).strip()
        for key, value in request.args.items()
        if key.lower().startswith("h_")
    }

    headers = {**default_headers, **request_headers}

    # Process URLs with new logic DaddyLive 2025
    processed_url = process_daddylive_url(m3u_url)

    try:
        print(f"Call to resolve_m3u8_link for processed URL: {processed_url}")
        result = resolve_m3u8_link(processed_url, headers)
        if not result["resolved_url"]:
            return "Error: Unable to resolve URL to valid M3U8.", 500

        resolved_url = result["resolved_url"]
        current_headers_for_proxy = result["headers"]

        print(f"Resolution completed. Final M3U8 URL: {resolved_url}")

        # FIX: Verify that it is a valid M3U8 (without proxy parameters)
        if not resolved_url.endswith('.m3u8'):
            print(f"Resolved URL is not an M3U8: {resolved_url}")
            return "Error: Unable to get valid M3U8 from channel", 500

        # Fetch actual M3U8 content from clean URL
        print(f"Fetching M3U8 content from clean URL: {resolved_url}")
        print(f"Using headers: {current_headers_for_proxy}")

        m3u_response = requests.get(resolved_url, headers=current_headers_for_proxy, allow_redirects=True, timeout=REQUEST_TIMEOUT, proxies=get_proxy_for_url(resolved_url), verify=VERIFY_SSL)
        m3u_response.raise_for_status()

        m3u_content = m3u_response.text
        final_url = m3u_response.url

        # Process M3U8 content
        file_type = detect_m3u_type(m3u_content)
        if file_type == "m3u":
            return Response(m3u_content, content_type="application/vnd.apple.mpegurl")

        # Process M3U8 content
        parsed_url = urlparse(final_url)
        base_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path.rsplit('/', 1)[0]}/"

        # Prepare header query for proxied segments/keys
        headers_query = "&".join([f"h_{quote(k)}={quote(v)}" for k, v in current_headers_for_proxy.items()])

        modified_m3u8 = []
        for line in m3u_content.splitlines():
            line = line.strip()
            if line.startswith("#EXT-X-KEY") and 'URI="' in line:
                line = replace_key_uri(line, headers_query)
            elif line and not line.startswith("#"):
                segment_url = urljoin(base_url, line)
                line = f"/proxy/ts?url={quote(segment_url)}&{headers_query}"
            modified_m3u8.append(line)

        modified_m3u8_content = "\n".join(modified_m3u8)

        # Save modified content in cache before returning
        M3U8_CACHE[cache_key] = modified_m3u8_content

        return Response(modified_m3u8_content, content_type="application/vnd.apple.mpegurl")

    except requests.RequestException as e:
        print(f"Error downloading or resolving file: {str(e)}")
        return f"Error downloading or resolving M3U/M3U8 file: {str(e)}", 500
    except Exception as e:
        print(f"Generic error in proxy_m3u function: {str(e)}")
        return f"Generic error while processing: {str(e)}", 500


@app.route('/proxy/resolve')
def proxy_resolve():
    # Proxy to resolve and return M3U8 URL with DaddyLive 2025 method
    url = request.args.get('url', '').strip()
    if not url:
        return "Error: Missing 'url' parameter", 400

    daddy_base_url = get_daddylive_base_url()
    daddy_origin = urlparse(daddy_base_url).scheme + "://" + urlparse(daddy_base_url).netloc

    # ADD: Default headers identical to /proxy/m3u
    default_headers = {
        "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36",
        "Referer": daddy_base_url,
        "Origin": daddy_origin
    }

    # Extract headers from request, overriding defaults
    request_headers = {
        unquote(key[2:]).replace("_", "-"): unquote(value).strip()
        for key, value in request.args.items()
        if key.lower().startswith("h_")
    }

    headers = {**default_headers, **request_headers}

    try:
        processed_url = process_daddylive_url(url)
        result = resolve_m3u8_link(processed_url, headers)
        if not result["resolved_url"]:
            return "Error: Unable to resolve URL", 500

        headers_query = "&".join([f"h_{quote(k)}={quote(v)}" for k, v in result["headers"].items()])
        return Response(
            f"#EXTM3U\n"
            f"#EXTINF:-1,Canale Risolto\n"
            f"/proxy/m3u?url={quote(result['resolved_url'])}&{headers_query}",
            content_type="application/vnd.apple.mpegurl"
        )

    except Exception as e:
        return f"Error resolving URL: {str(e)}", 500


@app.route('/proxy/ts')
def proxy_ts():
    # Proxy for .TS segments with custom headers and caching
    ts_url = request.args.get('url', '').strip()
    if not ts_url:
        return "Error: Missing 'url' parameter", 400

    # Check if the segment is cached
    if ts_url in TS_CACHE:
        print(f"Cache HIT for TS: {ts_url}")
        return Response(TS_CACHE[ts_url], content_type="video/mp2t")
    print(f"Cache MISS for TS: {ts_url}")

    headers = {
        unquote(key[2:]).replace("_", "-"): unquote(value).strip()
        for key, value in request.args.items()
        if key.lower().startswith("h_")
    }

    try:
        response = requests.get(ts_url, headers=headers, stream=True, allow_redirects=True, timeout=REQUEST_TIMEOUT, proxies=get_proxy_for_url(ts_url), verify=VERIFY_SSL)
        response.raise_for_status()

        # Let's define a generator to send streaming data to the client
        # and simultaneously build the content for the cache.
        def generate_and_cache():
            content_parts = []
            try:
                # Iterate over response chunks
                for chunk in response.iter_content(chunk_size=8192):
                    if chunk: # Filter keep-alive chunks
                        content_parts.append(chunk)
                        yield chunk
            finally:
                # Once streaming to the client is complete, we cache the segment.
                ts_content = b"".join(content_parts)
                if ts_content:
                    TS_CACHE[ts_url] = ts_content
                    print(f"Cached TS segment ({len(ts_content)} bytes) per: {ts_url}")

        return Response(generate_and_cache(), content_type="video/mp2t")

    except requests.RequestException as e:
        return f"Error downloading TS segment: {str(e)}", 500
        
@app.route('/proxy')
def proxy():
    # M3U list proxy that automatically adds /proxy/m3u?url= with IP before links
    m3u_url = request.args.get('url', '').strip()
    if not m3u_url:
        return "Error: Missing 'url' parameter", 400

    try:
        server_ip = request.host
        proxy_for_request = get_proxy_for_url(m3u_url)
        response = requests.get(m3u_url, timeout=REQUEST_TIMEOUT, proxies=proxy_for_request, verify=VERIFY_SSL)
        response.raise_for_status()
        m3u_content = response.text
        
        modified_lines = []
        # This list will accumulate header parameters for the *next* stream URL
        current_stream_headers_params = [] 

        for line in m3u_content.splitlines():
            line = line.strip()
            if line.startswith('#EXTHTTP:'):
                try:
                    json_str = line.split(':', 1)[1].strip()
                    headers_dict = json.loads(json_str)
                    for key, value in headers_dict.items():
                        encoded_key = quote(quote(key))
                        encoded_value = quote(quote(str(value)))
                        current_stream_headers_params.append(f"h_{encoded_key}={encoded_value}")
                except Exception as e:
                    print(f"ERROR: Error parsing #EXTHTTP '{line}': {e}")
                modified_lines.append(line)
            
            elif line.startswith('#EXTVLCOPT:'):
                try:
                    options_str = line.split(':', 1)[1].strip()
                    # Split by comma, then iterate through key=value pairs
                    for opt_pair in options_str.split(','):
                        opt_pair = opt_pair.strip()
                        if '=' in opt_pair:
                            key, value = opt_pair.split('=', 1)
                            key = key.strip()
                            value = value.strip().strip('"') # Remove potential quotes
                            
                            header_key = None
                            if key.lower() == 'http-user-agent':
                                header_key = 'User-Agent'
                            elif key.lower() == 'http-referer':
                                header_key = 'Referer'
                            elif key.lower() == 'http-cookie':
                                header_key = 'Cookie'
                            elif key.lower() == 'http-header': # For generic http-header option
                                # This handles cases like http-header=X-Custom: Value
                                full_header_value = value
                                if ':' in full_header_value:
                                    header_name, header_val = full_header_value.split(':', 1)
                                    header_key = header_name.strip()
                                    value = header_val.strip()
                                else:
                                    print(f"WARNING: Malformed http-header option in EXTVLCOPT: {opt_pair}")
                                    continue # Skip malformed header
                            
                            if header_key:
                                encoded_key = quote(quote(header_key))
                                encoded_value = quote(quote(value))
                                current_stream_headers_params.append(f"h_{encoded_key}={encoded_value}")
                            
                except Exception as e:
                    print(f"ERROR: Error parsing #EXTVLCOPT '{line}': {e}")
                modified_lines.append(line) # Keep the original EXTVLCOPT line in the output
            elif line and not line.startswith('#'):
                if 'pluto.tv' in line.lower():
                    modified_lines.append(line)
                else:
                    encoded_line = quote(line, safe='')
                    # Construct the headers query string from accumulated parameters
                    headers_query_string = ""
                    if current_stream_headers_params:
                        headers_query_string = "%26" + "%26".join(current_stream_headers_params)
                    
                    modified_line = f"http://{server_ip}/proxy/m3u?url={encoded_line}{headers_query_string}"
                    modified_lines.append(modified_line)
                
                # Reset headers for the next stream URL
                current_stream_headers_params = [] 
            else:
                modified_lines.append(line)
        
        modified_content = '\n'.join(modified_lines)
        parsed_m3u_url = urlparse(m3u_url)
        original_filename = os.path.basename(parsed_m3u_url.path)
        
        return Response(modified_content, content_type="application/vnd.apple.mpegurl", headers={'Content-Disposition': f'attachment; filename="{original_filename}"'})
        
    except requests.RequestException as e:
        proxy_used = proxy_for_request['http'] if proxy_for_request else "Nobody"
        print(f"ERRORE: Failed to download '{m3u_url}' using proxy.")
        return f"Error downloading M3U list: {str(e)}", 500
    except Exception as e:
        return f"generic error: {str(e)}", 500

@app.route('/proxy/key')
def proxy_key():
    # AES-128 Key Proxy with Custom Headers and Caching
    key_url = request.args.get('url', '').strip()
    if not key_url:
        return "Error: Missing 'url' parameter for key", 400

    # Controlla se la chiave è in cache
    if key_url in KEY_CACHE:
        print(f"Cache HIT for KEY: {key_url}")
        return Response(KEY_CACHE[key_url], content_type="application/octet-stream")
    print(f"Cache MISS for KEY: {key_url}")

    headers = {
        unquote(key[2:]).replace("_", "-"): unquote(value).strip()
        for key, value in request.args.items()
        if key.lower().startswith("h_")
    }

    try:
        response = requests.get(key_url, headers=headers, allow_redirects=True, timeout=REQUEST_TIMEOUT, proxies=get_proxy_for_url(key_url), verify=VERIFY_SSL)
        response.raise_for_status()
        key_content = response.content

        # Salva la chiave nella cache
        KEY_CACHE[key_url] = key_content
        return Response(key_content, content_type="application/octet-stream")

    except requests.RequestException as e:
        return f"Error downloading AES-128 key: {str(e)}", 500

@app.route('/')
def index():
    # Main page showing a welcome message
    base_url = get_daddylive_base_url()
    return f"Wot"

if __name__ == '__main__':
    # Use port 7860 by default, but allow it to be overridden with the PORT environment variable
    port = int(os.environ.get("PORT", 7860))
    print(f"Proxy ONLINE - Listening on port {port}")
    app.run(host="0.0.0.0", port=port, debug=False)
