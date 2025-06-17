import time

from resources.bcolors import bcolors
from session_recorder import decode_response_body

def replay_and_capture(driver, packet):
    # unpack
    url     = packet['url']
    method  = packet['method']
    headers = packet['headers']
    body    = packet.get('body', None)

    # send it in‐page:
    driver.execute_script("""
      window._replayPromise = fetch(arguments[0], {
        method: arguments[1],
        headers: arguments[2],
        body: arguments[3]
      }).then(r => r.text());
    """, url, method, headers, body)

    # give it a moment to fire in browser & be intercepted
    time.sleep(1)

    # pull out the matching request from Selenium-Wire’s log
    replay_reqs = [
      r for r in driver.requests
      if r.headers.get('X-Replay-Test') == 'true'
    ]
    if not replay_reqs:
        print(f"{bcolors.FAIL}[ERROR]: No replay request found in selenium-wire log!{bcolors.ENDC}")
        return

    last = replay_reqs[-1]
    status = last.response.status_code if last.response else 'no response'
    print(f"{bcolors.OKBLUE}[INFO]: Replayed → {method} {url}  status={status}{bcolors.ENDC}")

    if not last.response or not last.response.body:
        print(f"{bcolors.FAIL}[ERROR]: No response body found for the replayed request.{bcolors.ENDC}")
        return
    
    text = decode_response_body(last.response)
    snippet = text[:500].replace('\n',' ')
    print(f"Response snippet: {snippet!r}\n")
