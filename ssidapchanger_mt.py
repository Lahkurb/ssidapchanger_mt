import sys, paramiko, re, time, datetime, os, select, configparser, threading
from log_class import *



regtable = "/interface wireless registration-table print detail\r\n"

cfg = configparser.ConfigParser()
cfg.read('config.ini')

#TODO:check arguments
#if len(sys.argv) < 2:
#    print('''\nToo few arguments. Usage: ssidapchanger_mt.py <config_section> ''')
#    exit()

config = 'static_section'
#ip = sys.argv[2]
#TODO:check blank username
user = cfg[config]['LOGIN']
#TODO:check blank password
password = cfg[config]['PASSWORD']
#TODO: check is int 1-65535
port = cfg[config]['PORT']
timeout = 5
#TODO:check blank username
station_user = cfg[config]['STATION_USER']
#TODO:check blank password
station_pass = cfg[config]['STATION_PASS']
#TODO:check is IPv4
ip = cfg[config]['AP_IP']
wireless_setup = cfg[config]['WIRELESS_SETUP']
wireless_setup = wireless_setup.replace('\"', '')

file_debug = cfg[config]['DEBUG_FILE']
file_error = cfg[config]['ERROR_FILE']
log_dir = cfg[config]['LOG_DIR']
file_debug = log_dir + file_debug
file_error = log_dir + file_error
if not os.path.exists(log_dir.replace('\\', '')):
    os.makedirs(log_dir.replace('\\', ''))
log = Log(file_debug, file_error)

def confirmation(log):
    log.debug('on device: ' + ip + ' stations will be set with following configuration: \n\n' + wireless_setup + '\n' + 'press \'y\' if its correct')
    choice = input()
    if choice == 'y':
        log.debug('got config confirmation')
        return True
    else:
        log.debug('didnt get config confirmation')
        return False

def is_timeout(now):
    if(int(time.time()) > now + 30):
        log.debug(str(now))
        log.debug('timeout 30 s')
        log.error_log(ip, 'timeout 30 s')
        clean_flags()
        return True

def _get_data(channel, channel_data, log):
    timeout = 5
    r,w,e = select.select([channel], [], [], timeout)
    if channel in r:
        channel_data += channel.recv(9999)
        buf = channel_data.decode('utf-8')
        return buf
    else:
        log.debug('get_data t/o')
        return False

def get_prompt(buf, log):
    if buf.endswith('] > ') == True:
        log.debug(buf)
        log.debug('we found prompt')
        return True
    else:
        return False

def isMacAddress(buf):
    if buf.find('mac-address=') != -1 and buf.endswith('] > ') == True:
        log.debug('got mac-address and prompt')
        return True
    else:
        log.debug('didnt get mac-address list')
        return False

def stripedMacAddress(buf, log):
    mac_address = []
    lista_pmac = ([m.start() for m in re.finditer('mac-address=', buf)])
    for mac in lista_pmac:
        mac += 12 #ustawiamy x na koniec mac-address=
        mac_address.append(buf[mac+3:mac+20])
    if mac_address:
        log.debug('mac address list ready')
        log.debug('mac address count: ')
        log.debug(str(len(mac_address)))
        return mac_address
    else:
        log.debug('get mac address list failed ')
        return False

def clean_flags():
    quit_loop = True
    prompt = False
    counter = 0

def setMacTelnetSring(mac, log):
    macTelnetString = "/tool mac-telnet " + mac + '\r\n'
    return macTelnetString

def isStationAdminPrompt(buf, log):
    if buf.find('Login:') != -1:
        log.debug('station user prompt: ' + buf)
        return True
    else:
        log.debug('didnt get station admin prompt')
        return False

def isStationPassPrompt(buf, log):
    if buf.find('Password:') != -1:
        log.debug('station pass prompt: ' + buf)
        return True
    else:
        log.debug('didnt get station password prompt')
        return False

def stationLoginFailed(buf, log):
    if buf.find('Login failed, incorrect username or password') != -1:
        log.debug('login failed')
        return True
    else:
        return False

def isWelcomeBack(buf, log):
    if buf.find('Welcome back!') != -1:
        log.debug('We got Welcome back! Connection refused' + buf)
        return True
    else:
        return False
        
def convertMac(mac):
    mac = mac.replace(':', '-')
    mac = mac + '.txt'
    return mac    

def station_task(mac):
    buf = ''
    channel_data = bytes()
    converted_mac = convertMac(mac)
    log = Log(log_dir + converted_mac, log_dir + converted_mac)
    log.debug('station_task for mac: ' + mac )
    macTelnetString =  setMacTelnetSring(mac, log)
    try:
        #new connection to ap each thread. MT dont support other solution
        client = paramiko.SSHClient()
        client.load_system_host_keys()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(ip, port=port, username=user, password=password)
        log.debug("logged in\n")
        now = int(time.time())
        channel = client.invoke_shell()
        while True:
            timeout = 5
            r,w,e = select.select([channel], [], [], timeout)
            if channel in r:
                channel_data += channel.recv(9999)
                buf = channel_data.decode('utf-8')
                if get_prompt(buf, log):
                    channel.send(macTelnetString)
                    while True:
                        timeout = 5
                        channel_data = bytes()
                        r,w,e = select.select([channel], [], [], timeout)
                        if channel in r:
                            channel_data += channel.recv(9999)
                            buf = channel_data.decode('utf-8')
                            log.debug('looking for station admin prompt in buf: ' + buf)
                            if isStationAdminPrompt(buf, log):
                                channel.send(station_user + '\n')
                                while True:
                                    timeout = 5
                                    channel_data = bytes()
                                    r,w,e = select.select([channel], [], [], timeout)
                                    if channel in r:
                                        channel_data += channel.recv(9999)
                                        buf = channel_data.decode('utf-8')
                                        log.debug('looking for station pass prompt in buf: ' + buf)
                                        if isStationPassPrompt(buf, log):
                                            channel.send(station_pass + '\r\n')
                                            while True:
                                                timeout = 5
                                                r,w,e = select.select([channel], [], [], timeout)
                                                if channel in r:
                                                    channel_data += channel.recv(9999)
                                                    buf = channel_data.decode('utf-8')
                                                    log.debug('checking login fail, connection refuse and prompt in buf: ' + buf)
                                                    if stationLoginFailed(buf, log) or isWelcomeBack(buf, log):
                                                        client.close()
                                                        sys.exit()
                                                    elif get_prompt(buf, log):
                                                        log.debug('mac telnet loging success')
                                                        channel.send(wireless_setup + '\r\n')
                                                        log.debug('wireless_setup sended')
                                                        time.sleep(2)
                                                        client.close()
                                                        sys.exit()
                                                log.debug("t/o")
                                                if is_timeout(now):
                                                    break        
                                    log.debug("station pass prompt t/o")
                                    if is_timeout(now):
                                        break      
                        log.debug("station user prompt t/o")
                        if is_timeout(now):
                            break
            log.debug("station prompt t/o")
            if is_timeout(now):
                break
    except paramiko.ssh_exception.AuthenticationException as ssherr:
        log.debug(str(ssherr))
        client.close()
    except paramiko.ssh_exception.SSHException as ssherr:
        log.debug(str(ssherr))
        client.close()
    except paramiko.ssh_exception.socket.error as ssherr:
        log.debug(str(ssherr))
        client.close()
    except paramiko.ssh_exception.BadHostKeyException as ssherr:
        log.debug(str(ssherr))
        client.close()
    finally:
        client.close()
        
class run_thread(threading.Thread):
    def __init__(self, mac, counter):
        threading.Thread.__init__(self)
        self.mac = mac
        self.counter = counter
    def run(self):
        log.debug('####### thread number: ' + str(self.counter) + ' , thread mac: ' + self.mac + ' ######\n')
        result = station_task(self.mac)
        #log("%s zakonczony %s" % (self.counter, result))
        #log.debug('####### thread number: #####')
        #log.debug(str(self.counter))
        #log.debug(self.mac)

'''-------------------------'''   
try:
    buf = ''
    channel_data = bytes()
    client = paramiko.SSHClient()
    if not confirmation(log):
        sys.exit()

    client.load_system_host_keys()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(ip, port=port, username=user, password=password)
    log.debug("logged in\n")
    now = int(time.time())
    counter = 0
    channel = client.invoke_shell()
    while True:
        timeout = 5
        r,w,e = select.select([channel], [], [], timeout)
        if channel in r:
            channel_data += channel.recv(9999)
            buf = channel_data.decode('utf-8')
            if get_prompt(buf, log):
                prompt = True
                channel.send(regtable)
                while prompt == True:
                    timeout = 5
                    r,w,e = select.select([channel], [], [], timeout)
                    if channel in r:
                        channel_data += channel.recv(9999)
                        buf = channel_data.decode('utf-8')
                        if isMacAddress(buf):
                            mac_list = stripedMacAddress(buf, log)
                            if mac_list != False:
                                log.debug('mac list: ' + str(mac_list))
                                for mac in mac_list:
                                    log.debug('calling thread for mac:' + mac)
                                    counter += 1
                                    run_thread(mac, counter).start()
                                log.debug('end of main thread')
                                #moze by poczekac i sprawdzic watki?
                                client.close()
                                sys.exit()
                            else:
                                log.debug('didnt get mac address list')
                                clean_flags()
                                break
                    log.debug("get mac address t/o")
                    if is_timeout(now):
                        break
        log.debug("prompt t/o")
        if is_timeout(now):
            break
except paramiko.ssh_exception.AuthenticationException as ssherr:
    log.debug(str(ssherr))
    client.close()
except paramiko.ssh_exception.SSHException as ssherr:
    log.debug(str(ssherr))
    client.close()
except paramiko.ssh_exception.socket.error as ssherr:
    log.debug(str(ssherr))
    client.close()
except paramiko.ssh_exception.BadHostKeyException as ssherr:
    log.debug(str(ssherr))
    client.close()
finally:
    client.close()
log.debug("done")
	