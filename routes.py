# routes.py
import socket
import subprocess
import re
import requests
from datetime import datetime
from flask import request, render_template, redirect, url_for, jsonify
import db # db.py dosyasını import ediyoruz
import sys # sys modülünü ekledik

# --- SNMP OID Tanımları ---
# HOST-RESOURCES-MIB
OID_CPU_LOAD = "1.3.6.1.2.1.25.3.3.1.2" # hrDeviceProcessorLoad (Gauge32)
OID_MEMORY_SIZE = "1.3.6.1.2.1.25.2.2.0" # hrMemorySize.0 (Total RAM in KBytes, Gauge32)

# hrStorageTable (Disk ve RAM detayları için)
OID_HR_STORAGE_TABLE = "1.3.6.1.2.1.25.2.3.1"
OID_HR_STORAGE_DESCR = OID_HR_STORAGE_TABLE + ".3" # hrStorageDescr (STRING)
OID_HR_STORAGE_TYPE = OID_HR_STORAGE_TABLE + ".2" # hrStorageType (OID)
OID_HR_STORAGE_ALLOCATION_UNITS = OID_HR_STORAGE_TABLE + ".4" # hrStorageAllocationUnits (INTEGER)
OID_HR_STORAGE_SIZE = OID_HR_STORAGE_TABLE + ".5" # hrStorageSize (INTEGER)
OID_HR_STORAGE_USED = OID_HR_STORAGE_TABLE + ".6" # hrStorageUsed (INTEGER)

# Standart Sistem Bilgisi
OID_SYS_DESCR = "1.3.6.1.2.1.1.1.0" # sysDescr.0
OID_SYS_UPTIME = "1.3.6.1.2.1.1.3.0" # sysUpTime.0
OID_SYS_CONTACT = "1.3.6.1.2.1.1.4.0" # sysContact.0
OID_SYS_NAME = "1.3.6.1.2.1.1.5.0" # sysName.0
OID_SYS_LOCATION = "1.3.6.1.2.1.1.6.0" # sysLocation.0
OID_SYS_SERVICES = "1.3.6.1.2.1.1.7.0" # sysServices.0
OID_SYS_OBJECT_ID = "1.3.6.1.2.1.1.2.0" # sysObjectID.0

# TCP Bağlantıları
OID_TCP_CONN_STATE = "1.3.6.1.2.1.6.13.1.1" # tcpConnState (established bağlantı sayısını bulmak için)

# Sıcaklık (Bazı cihazlarda bulunur, standart OID olmayabilir)
OID_TEMP_SENSOR = "1.3.6.1.4.1.2021.13.16.1.1.4.1" # UCD-SNMP-MIB::ucdavis.la.temp.tempTable.tempEntry.tempValue.1

# Ağ Arayüzleri
OID_IF_TABLE = "1.3.6.1.2.1.2.2.1" # ifTable
OID_IF_DESCR = OID_IF_TABLE + ".2" # ifDescr
OID_IF_SPEED = OID_IF_TABLE + ".5" # ifSpeed
OID_IF_PHYS_ADDRESS = OID_IF_TABLE + ".6" # ifPhysAddress
OID_IF_OPER_STATUS = OID_IF_TABLE + ".8" # ifOperStatus
OID_IF_IN_OCTETS = OID_IF_TABLE + ".10" # ifInOctets
OID_IF_OUT_OCTETS = OID_IF_TABLE + ".16" # ifOutOctets


# --- Rota Tanımları ---
def register_routes(app, _get_snmp_value_func, _snmpwalk_parse_table_func, _run_internet_speedtest):
    """Flask uygulaması için rotaları kaydeder."""

    # Yardımcı fonksiyonları global olarak kullanılabilir hale getir (veya doğrudan kullan)
    # Bu fonksiyonlar app.py'den pass edildiği için burada kullanılabilir.
    global _get_snmp_value, _snmpwalk_parse_table
    _get_snmp_value = _get_snmp_value_func
    _snmpwalk_parse_table = _snmpwalk_parse_table_func

    @app.route("/")
    def index():
        """Ana kontrol paneli sayfasını gösterir."""
        recent_scans = db.get_recent_scan_records(limit=5)
        cihazlar = db.get_all_devices()
        active_alert_count = db.get_active_alert_count()
        
        # Genel durum belirleme
        overall_status = "Normal"
        if active_alert_count > 0:
            overall_status = "Uyarı"

        total_devices = db.get_total_device_count()

        # index.html'e gönderilecek varsayılan hata mesajları ve SNMP veri değişkenleri
        cpu_error = {"message": "Veri Yok", "type": "info"}
        ram_error = {"message": "Veri Yok", "type": "info"}
        disk_error = {"message": "Veri Yok", "type": "info"}
        iface_error = {"message": "Veri Yok", "type": "info"}
        sysinfo_error = {"message": "Veri Yok", "type": "info"}
        uptime_error = {"message": "Veri Yok", "type": "info"}
        temp_error = {"message": "Veri Yok", "type": "info"}
        conn_error = {"message": "Veri Yok", "type": "info"}
        general_error = None

        # SNMP veri değişkenlerini None veya boş liste/sözlük olarak başlat
        cpu_values = []
        total_ram_kbytes = None
        ram_kbytes = None
        ram_used_percent = None
        disks = []
        interfaces = []
        parsed_sysinfo = []
        uptime_ticks = None
        temperature = None
        established_connections = None


        return render_template("index.html", 
                               recent_scans=recent_scans, 
                               cihazlar=cihazlar,
                               active_alert_count=active_alert_count,
                               overall_status=overall_status,
                               total_devices=total_devices,
                               cpu_error=cpu_error,
                               ram_error=ram_error,
                               disk_error=disk_error,
                               iface_error=iface_error,
                               sysinfo_error=sysinfo_error,
                               uptime_error=uptime_error,
                               temp_error=temp_error,
                               conn_error=conn_error,
                               general_error=general_error,
                               # SNMP veri değişkenleri de eklendi
                               cpu_values=cpu_values,
                               total_ram_kbytes=total_ram_kbytes,
                               ram_kbytes=ram_kbytes,
                               ram_used_percent=ram_used_percent,
                               disks=disks,
                               interfaces=interfaces,
                               sysinfo_lines=parsed_sysinfo,
                               uptime_ticks=uptime_ticks,
                               temperature=temperature,
                               established_connections=established_connections
                               )

    @app.route("/ping")
    def ping_tool():
        """Ping testi yapar ve sonucu gösterir veya formu sunar."""
        ip = request.args.get("ip")
        if not ip:
            return render_template("ping.html") # IP yoksa formu göster

        print(f"DEBUG: Ping testi başlatılıyor: {ip}")
        sys.stdout.flush()
        try:
            # -c: paket sayısı, -w: timeout
            cmd = ["ping", "-c", "4", "-W", "2", ip] # 2 saniye timeout
            print(f"DEBUG: Ping komutu: {' '.join(cmd)}")
            sys.stdout.flush()
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=15, check=True)
            output = result.stdout
            print(f"DEBUG: Ping komut çıktısı:\n{output}")
            sys.stdout.flush()

            # Ortalama gecikme (latency)
            latency_match = re.search(r"min/avg/max/mdev = [\d.]+/([\d.]+)/", output)
            latency = latency_match.group(1) if latency_match else "N/A"

            # Jitter (mdev)
            jitter_match = re.search(r"min/avg/max/mdev = [\d.]+/[\d.]+/[\d.]+/([\d.]+)", output)
            jitter = jitter_match.group(1) if jitter_match else "N/A"

            # Paket kaybı
            packet_loss_match = re.search(r"(\d+)% packet loss", output)
            packet_loss = packet_loss_match.group(1) if packet_loss_match else "N/A"

            return render_template("ping_result.html", ip=ip, latency=latency, jitter=jitter, packet_loss=packet_loss, output=output)
        except subprocess.CalledProcessError as e:
            print(f"ERROR: Ping komutu başarısız oldu: {e.stderr}")
            sys.stdout.flush()
            return render_template("ping_result.html", ip=ip, latency="Hata", jitter="Hata", packet_loss="Hata", output=f"Ping komutu başarısız oldu: {e.stderr}")
        except subprocess.TimeoutExpired:
            print(f"ERROR: Ping zaman aşımına uğradı: {ip}")
            sys.stdout.flush()
            return render_template("ping_result.html", ip=ip, latency="Zaman Aşımı", jitter="N/A", packet_loss="100", output=f"Ping zaman aşımına uğradı: {ip} adresine ulaşılamıyor.")
        except FileNotFoundError:
            print("ERROR: Ping komutu bulunamadı.")
            sys.stdout.flush()
            return render_template("ping_result.html", ip=ip, latency="Hata", jitter="Hata", packet_loss="Hata", output="Ping komutu bulunamadı. Lütfen Dockerfile'ı kontrol edin.")
        except Exception as e:
            print(f"ERROR: Ping testi sırasında beklenmeyen hata: {e}")
            sys.stdout.flush()
            return render_template("ping_result.html", ip=ip, latency="Hata", jitter="Hata", packet_loss="Hata", output=f"Beklenmeyen bir hata oluştu: {e}")


    @app.route("/portscan")
    def portscan_tool():
        """Port taraması yapar ve sonucu gösterir veya formu sunar."""
        ip = request.args.get("ip")
        portlar_str = request.args.get("portlar")
        
        if not ip or not portlar_str:
            return render_template("portscan.html") # IP veya port yoksa formu göster

        portlar = [int(p.strip()) for p in portlar_str.split(',') if p.strip().isdigit()]
        results = []

        for port in portlar:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1) # 1 saniye timeout
            start_time = datetime.now()
            durum = "Kapalı"
            servis = "Bilinmiyor"
            gecikme = "N/A"

            try:
                conn_result = sock.connect_ex((ip, port))
                end_time = datetime.now()
                gecikme_ms = (end_time - start_time).total_seconds() * 1000

                if conn_result == 0:
                    durum = "Açık"
                    gecikme = f"{gecikme_ms:.2f}"
                    try:
                        servis = socket.getservbyport(port)
                    except OSError:
                        servis = "Bilinmeyen Servis"
                else:
                    durum = "Kapalı"
                    gecikme = f"{gecikme_ms:.2f}" # Kapalı portlar için de gecikmeyi göster
            except socket.timeout:
                durum = "Zaman Aşımı"
                gecikme = "Zaman Aşımı"
            except socket.error as e:
                durum = f"Hata ({e})"
                gecikme = "Hata"
            finally:
                sock.close()
            
            results.append({"port": port, "durum": durum, "gecikme": gecikme, "servis": servis})
            db.add_scan_record(ip, port, durum, gecikme, datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

        return render_template("portscan_result.html", ip=ip, results=results)



    # BU SATIRIN BAŞINDA KESİNLİKLE HİÇBİR BOŞLUK OLMAYACAK.
    # 'def register_routes' ile aynı girinti seviyesinde olmalı (yani, dosyanın en sol kenarından itibaren hiç boşluksuz).
    @app.route("/traceroute", methods=["GET"])
    def traceroute_tool():
        # Bu fonksiyonun tüm içeriği, 'def traceroute_tool():' satırına göre
        # standart Python girintisiyle (genellikle 4 boşluk) girintili olmalıdır.
        print("DEBUG: traceroute_tool fonksiyonuna girildi.")
        sys.stdout.flush()

        target_ip = request.args.get("ip")
        if not target_ip:
            print("DEBUG: IP adresi belirtilmedi, formu gösteriyor.")
            sys.stdout.flush()
            return render_template("traceroute.html", result=None)

        print(f"DEBUG: Hedef IP: {target_ip} için traceroute başlatılıyor.")
        sys.stdout.flush()

        output = ""
        try:
            command = ["traceroute", "-n", "-w", "1", "-q", "1", target_ip]
            print(f"DEBUG: Çalıştırılacak komut: {' '.join(command)}")
            sys.stdout.flush()

            process = subprocess.run(command, capture_output=True, text=True, check=True, timeout=20)
            output = process.stdout
            print(f"DEBUG: Traceroute komutunun ham çıktısı:\n{output}")
            sys.stdout.flush()

        except subprocess.TimeoutExpired as e:
            print(f"ERROR: Traceroute zaman aşımına uğradı ({target_ip}): {e}")
            sys.stdout.flush()
            return render_template("traceroute_result.html", ip=target_ip,
                                   hops=[], geo_data=[],
                                   raw_output=f"Traceroute zaman aşımına uğradı: {target_ip} adresine ulaşılamıyor.")
        except subprocess.CalledProcessError as e:
            print(f"ERROR: Traceroute komutu hatası ({target_ip}): {e.stderr}")
            sys.stdout.flush()
            return render_template("traceroute_result.html", ip=target_ip,
                                   hops=[], geo_data=[],
                                   raw_output=f"Traceroute komutu başarısız oldu: {e.stderr}")
        except FileNotFoundError:
            print("ERROR: Traceroute komutu bulunamadı. Lütfen Dockerfile'ı kontrol edin.")
            sys.stdout.flush()
            return render_template("traceroute_result.html", ip=target_ip,
                                   hops=[], geo_data=[],
                                   raw_output="Traceroute komutu bulunamadı. Lütfen Dockerfile'ı kontrol edin.")
        except Exception as e:
            print(f"CRITICAL ERROR: Traceroute testi sırasında beklenmeyen bir hata oluştu: {e}")
            import traceback
            traceback.print_exc()
            sys.stdout.flush()
            return render_template("traceroute_result.html", ip=target_ip,
                                   hops=[], geo_data=[],
                                   raw_output=f"Beklenmeyen bir hata oluştu: {e}")

        traceroute_raw_hops = []
        print("DEBUG: Traceroute çıktısı ayrıştırma başlatılıyor.")
        sys.stdout.flush()

        for line in output.splitlines():
            if not line.strip() or "traceroute to" in line.lower():
                print(f"DEBUG: Skipping empty or header line: {line}")
                sys.stdout.flush()
                continue

            print(f"DEBUG: Processing line for parsing: {line}")
            sys.stdout.flush()

            hop_num = None
            hop_ip = None
            hop_hostname = None
            avg_time = None

            match = re.search(r'^\s*(\d+)\s+(?:(\S+)\s*)?(?:\(((\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}))\))?.*', line)

            if match:
                try:
                    hop_num = int(match.group(1))
                except ValueError:
                    print(f"WARNING: Atlama numarası geçersiz. Satır atlanıyor: {line}")
                    sys.stdout.flush()
                    continue
                
                extracted_name_or_ip_first_part = match.group(2)
                extracted_ip_in_parens = match.group(4)

                if extracted_ip_in_parens:
                    hop_ip = extracted_ip_in_parens
                    if extracted_name_or_ip_first_part:
                        hop_hostname = extracted_name_or_ip_first_part
                    else:
                        hop_hostname = hop_ip
                elif extracted_name_or_ip_first_part:
                    if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', extracted_name_or_ip_first_part):
                        hop_ip = extracted_name_or_ip_first_part
                        hop_hostname = hop_ip
                    elif extracted_name_or_ip_first_part == '*':
                        hop_ip = "*"
                        hop_hostname = "*"
                    else:
                        hop_hostname = extracted_name_or_ip_first_part
                        ip_match_anywhere = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', line[match.end():])
                        if ip_match_anywhere:
                            hop_ip = ip_match_anywhere.group(1)
                elif "*" in line:
                    hop_ip = "*"
                    hop_hostname = "*"
                else:
                    hop_ip = "Bilinmiyor"
                    hop_hostname = "Bilinmiyor"

                times_ms = re.findall(r'(\d+\.\d+)\s*ms', line)
                avg_time = float(times_ms[0]) if times_ms else None

                delays_list = []
                if avg_time is not None:
                    delays_list.append(f"{avg_time:.3f} ms")

                traceroute_raw_hops.append({
                    "hop_num": hop_num,
                    "hostname": hop_hostname,
                    "ip": hop_ip,
                    "delays": delays_list,
                    "avg_time_ms": avg_time
                })
                print(f"DEBUG: Ayrıştırılan atlama (ham): Hop {hop_num}, IP: {hop_ip}, Hostname: {hop_hostname}, Süre: {avg_time}ms, Gecikmeler: {delays_list}")
                sys.stdout.flush()
            else:
                print(f"WARNING: Satır, beklenen atlama formatıyla eşleşmedi. Atlanıyor: {line}")
                sys.stdout.flush()
                continue
                
        final_traceroute_details = []
        geo_data_for_map = []

        for hop_detail in traceroute_raw_hops:
            current_hop_ip = hop_detail["ip"]
            current_hop_num = hop_detail["hop_num"]
            
            hop_location = None

            if current_hop_ip and current_hop_ip != "*" and current_hop_ip != "127.0.0.1" and \
               not current_hop_ip.startswith("10.") and \
               not (current_hop_ip.startswith("172.") and len(current_hop_ip.split('.')) > 1 and 16 <= int(current_hop_ip.split('.')[1]) <= 31) and \
               not current_hop_ip.startswith("192.168."):
                
                print(f"DEBUG: {current_hop_ip} için coğrafi konum sorgusu yapılıyor.")
                sys.stdout.flush()
                try:
                    geo_response = requests.get(f"http://ip-api.com/json/{current_hop_ip}?fields=lat,lon,city,country,regionName", timeout=5)
                    geo_response.raise_for_status()
                    geo_data_raw = geo_response.json()
                    
                    if not isinstance(geo_data_raw, dict) or geo_data_raw.get('status') == 'fail':
                        print(f"WARNING: IP-API konum sorgusu başarısız veya geçersiz yanıt ({current_hop_ip}). Yanıt: {geo_data_raw}")
                        sys.stdout.flush()
                    elif geo_data_raw.get('lat') is not None and geo_data_raw.get('lon') is not None:
                        hop_location = {
                            "city": geo_data_raw.get('city', 'Bilinmiyor'),
                            "region": geo_data_raw.get('regionName', ''),
                            "country": geo_data_raw.get('country', 'Bilinmiyor')
                        }
                        geo_data_for_map.append({
                            "hop_num": current_hop_num,
                            "ip": current_hop_ip,
                            "lat": geo_data_raw['lat'],
                            "lon": geo_data_raw['lon'],
                            "city": geo_data_raw.get('city', 'Bilinmiyor'),
                            "country": geo_data_raw.get('country', 'Bilinmiyor')
                        })
                        print(f"DEBUG: {current_hop_ip} için konum verisi eklendi: Lat {geo_data_raw['lat']}, Lon {geo_data_raw['lon']}")
                        sys.stdout.flush()
                    else:
                        print(f"WARNING: {current_hop_ip} için konum verisinde lat/lon eksik veya geçersiz: {geo_data_raw}")
                        sys.stdout.flush()
                except requests.exceptions.RequestException as req_e:
                    print(f"WARNING: Coğrafi konum API isteği hatası ({current_hop_ip}): {req_e}")
                    sys.stdout.flush()
                except Exception as geo_e:
                    print(f"WARNING: Coğrafi konum alınırken veya işlenirken genel hata ({current_hop_ip}): {geo_e}")
                    sys.stdout.flush()
            else:
                print(f"DEBUG: {current_hop_ip} (dahili veya geçersiz IP) için coğrafi konum sorgusu atlanıyor.")
                sys.stdout.flush()
            
            hop_detail["location"] = hop_location
            final_traceroute_details.append(hop_detail)


        print(f"DEBUG: Toplam ayrıştırılan atlama detayı: {len(final_traceroute_details)}")
        print(f"DEBUG: Toplam geo veri: {len(geo_data_for_map)}")
        print("DEBUG: traceroute_result.html şablonu render ediliyor.")
        sys.stdout.flush()
        return render_template("traceroute_result.html", ip=target_ip,
                               hops=final_traceroute_details,
                               geo_data=geo_data_for_map, raw_output=output)

    # SNMP Subprocess rotası - Hem GET hem POST isteklerini işler
    @app.route("/snmp_subprocess", methods=["GET", "POST"])
    def snmp_subprocess():
        """SNMP sorguları yapar ve sonuçları gösterir."""
        ip = None
        community = "public" # Varsayılan değer

        if request.method == "POST":
            ip = request.form.get("ip")
            community = request.form.get("community", "public")
        elif request.method == "GET":
            ip = request.args.get("ip")
            community = request.args.get("community", "public")

        if not ip:
            # Eğer IP adresi yoksa, sadece formu göster
            return render_template("snmp_form.html")

        print(f"DEBUG: SNMP sorgusu başlatılıyor: IP={ip}, Community={community}")
        sys.stdout.flush()

        cpu_values = []
        total_ram_kbytes = None
        ram_kbytes = None # Başlangıçta None olarak tanımlandı
        ram_used_percent = None
        disks = []
        interfaces = []
        parsed_sysinfo = [] # Ayrıştırılmış sistem bilgisi
        uptime_ticks = None
        temperature = None
        established_connections = None
        
        # Hata mesajları için boş sözlükler
        cpu_error = {"message": "Veri Yok", "type": "info"}
        ram_error = {"message": "Veri Yok", "type": "info"}
        disk_error = {"message": "Veri Yok", "type": "info"}
        iface_error = {"message": "Veri Yok", "type": "info"}
        sysinfo_error = {"message": "Veri Yok", "type": "info"}
        uptime_error = {"message": "Veri Yok", "type": "info"}
        temp_error = {"message": "Veri Yok", "type": "info"}
        conn_error = {"message": "Veri Yok", "type": "info"}
        general_error = None # Genel bir hata mesajı

        # SNMP CPU Yükü
        try:
            # _get_snmp_value fonksiyonu tek bir değer için daha uygun, ancak CPU birden fazla çekirdek olabilir
            # Bu yüzden snmpwalk kullanmaya devam edebiliriz, ancak çıktıyı daha dikkatli ayrıştırmalıyız.
            cmd_cpu = ["snmpwalk", "-v2c", "-c", community, ip, OID_CPU_LOAD]
            print(f"DEBUG: SNMP CPU komutu: {' '.join(cmd_cpu)}")
            sys.stdout.flush()
            cpu_result = subprocess.run(cmd_cpu, capture_output=True, text=True, timeout=10, check=True)
            for line in cpu_result.stdout.strip().splitlines():
                # HOST-RESOURCES-MIB::hrProcessorLoad.196608 = INTEGER: 1
                match = re.search(r'INTEGER:\s*(\d+)', line)
                if match:
                    try:
                        load = int(match.group(1))
                        cpu_values.append(load)
                    except ValueError:
                        pass
            if not cpu_values:
                cpu_error = {"message": "CPU verisi alınamadı veya ayrıştırılamadı. Hedef cihazda CPU OID'si desteklenmiyor olabilir.", "type": "warning"}
            print(f"DEBUG: CPU verileri: {cpu_values}")
            sys.stdout.flush()
        except subprocess.CalledProcessError as e:
            cpu_error = {"message": f"CPU sorgusu başarısız oldu: {e.stderr.strip()}", "type": "danger"}
            print(f"ERROR: CPU sorgusu hatası: {e.stderr}")
            sys.stdout.flush()
        except subprocess.TimeoutExpired:
            cpu_error = {"message": "CPU sorgusu zaman aşımına uğradı.", "type": "danger"}
            print("ERROR: CPU sorgusu zaman aşımı.")
            sys.stdout.flush()
        except FileNotFoundError:
            cpu_error = {"message": "SNMP komutu bulunamadı.", "type": "danger"}
            print("ERROR: SNMP komutu bulunamadı.")
            sys.stdout.flush()
        except Exception as e:
            cpu_error = {"message": f"CPU verisi işlenirken hata: {e}", "type": "danger"}
            print(f"ERROR: CPU işleme hatası: {e}")
            sys.stdout.flush()

        # SNMP RAM Kullanımı
        try:
            # hrMemorySize.0 = INTEGER: 950024 KBytes gibi çıktıyı işlemek için
            total_ram_kbytes = _get_snmp_value(ip, community, OID_MEMORY_SIZE, type_prefix="INTEGER")
            print(f"DEBUG: Toplam RAM (KB): {total_ram_kbytes}")
            sys.stdout.flush()

            if total_ram_kbytes is not None and total_ram_kbytes > 0:
                hr_storage_column_oids = {
                    '2': 'type', # BURADA 'type' OID'sini de çekiyoruz
                    '3': 'descr',
                    '4': 'allocation_units',
                    '5': 'size',
                    '6': 'used'
                }
                storage_data = _snmpwalk_parse_table(ip, community, OID_HR_STORAGE_TABLE, hr_storage_column_oids)
                print(f"DEBUG: Storage Data: {storage_data}")
                sys.stdout.flush()

                physical_memory_entry = None
                for idx, item in storage_data.items():
                    # _snmpwalk_parse_table'dan gelen 'type' alanı 'RAM' string'ine eşit mi kontrol et
                    # OID .1.3.6.1.2.1.25.2.1.2 'RAM' tipi için
                    if item.get('type') == 'RAM' or item.get('descr') == "Physical memory":
                        if 'allocation_units' in item and 'used' in item:
                            # Düzeltme: used_units * allocation_units (Bytes) / 1024 (KBytes)
                            ram_kbytes = (item['used'] * item['allocation_units']) / 1024
                            physical_memory_entry = item # physical_memory_entry'yi de güncelledik
                            break # İlk bulunan RAM'i al
                
                if ram_kbytes is not None and total_ram_kbytes > 0: # ram_kbytes'ı kontrol et
                    ram_used_percent = (ram_kbytes / total_ram_kbytes) * 100
                else:
                    ram_error = {"message": "RAM kullanım detayı alınamadı (hrStorageTable üzerinden veya ayrıştırma hatası)." , "type": "warning"}
            else:
                ram_error = {"message": "Toplam RAM verisi alınamadı veya sıfır.", "type": "warning"}
            print(f"DEBUG: RAM kullanım yüzdesi: {ram_used_percent}")
            sys.stdout.flush()
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired, FileNotFoundError) as e:
            ram_error = {"message": f"RAM sorgusu hatası: {e}", "type": "danger"}
            print(f"ERROR: RAM sorgusu hatası: {e}")
            sys.stdout.flush()
        except Exception as e:
            ram_error = {"message": f"RAM verisi işlenirken hata: {e}", "type": "danger"}
            print(f"ERROR: RAM işleme hatası: {e}")
            sys.stdout.flush()

        # SNMP Disk Bilgileri
        try:
            disk_column_oids = {
                '2': 'type', # BURADA 'type' OID'sini de çekiyoruz
                '3': 'descr', # hrStorageDescr
                '4': 'allocation_units', # hrStorageAllocationUnits
                '5': 'size', # hrStorageSize
                '6': 'used' # hrStorageUsed
            }
            raw_disks_data = _snmpwalk_parse_table(ip, community, OID_HR_STORAGE_TABLE, disk_column_oids)
            print(f"DEBUG: Raw Disks Data: {raw_disks_data}")
            sys.stdout.flush()
            
            for idx, d_item in raw_disks_data.items():
                # Sadece sabit diskleri filtrele (type 'Fixed Disk' olmalı)
                if d_item.get('descr') and d_item.get('type') == 'Fixed Disk' and \
                   d_item.get('allocation_units') is not None and \
                   d_item.get('size') is not None and \
                   d_item.get('used') is not None:
                    
                    total_bytes = d_item['size'] * d_item['allocation_units']
                    used_bytes = d_item['used'] * d_item['allocation_units']
                    
                    total_gb = round(total_bytes / (1024**3), 2)
                    used_gb = round(used_bytes / (1024**3), 2)
                    usage_percent = round((used_bytes / total_bytes) * 100, 2) if total_bytes > 0 else 0

                    disks.append({
                        "descr": d_item['descr'],
                        "total_gb": total_gb,
                        "used_gb": used_gb,
                        "usage_percent": usage_percent
                    })
            if not disks:
                disk_error = {"message": "Disk verisi alınamadı veya ayrıştırılamadı. Hedef cihazda Disk OID'si desteklenmiyor olabilir.", "type": "warning"}
            print(f"DEBUG: Disks: {disks}")
            sys.stdout.flush()
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired, FileNotFoundError) as e:
            disk_error = {"message": f"Disk sorgusu hatası: {e}", "type": "danger"}
            print(f"ERROR: Disk sorgusu hatası: {e}")
            sys.stdout.flush()
        except Exception as e:
            disk_error = {"message": f"Disk verisi işlenirken hata: {e}", "type": "danger"}
            print(f"ERROR: Disk işleme hatası: {e}")
            sys.stdout.flush()

        # SNMP Ağ Arayüzleri
        try:
            iface_column_oids = {
                '2': 'descr', # ifDescr
                '5': 'speed', # ifSpeed
                '6': 'phys_address', # ifPhysAddress
                '8': 'oper_status', # ifOperStatus
                '10': 'in_octets', # ifInOctets
                '16': 'out_octets' # ifOutOctets
            }
            raw_interfaces_data = _snmpwalk_parse_table(ip, community, OID_IF_TABLE, iface_column_oids)
            print(f"DEBUG: Raw Interfaces Data: {raw_interfaces_data}")
            sys.stdout.flush()

            # Operasyonel durumları okunabilir stringlere çevir
            oper_status_map = {
                1: "up", 2: "down", 3: "testing", 4: "unknown", 5: "dormant", 6: "notPresent", 7: "lowerLayerDown"
            }

            for idx, i_item in raw_interfaces_data.items():
                if i_item.get('descr'): # Sadece açıklaması olan arayüzleri al
                    interfaces.append({
                        "index": idx, # JavaScript için indeks de eklendi
                        "descr": i_item.get('descr'),
                        "speed_mbps": round(i_item.get('speed', 0) / 1_000_000, 2) if i_item.get('speed') is not None else 'N/A', # bps'den Mbps'ye
                        "phys_address": i_item.get('phys_address'),
                        "oper_status": oper_status_map.get(i_item.get('oper_status'), 'Bilinmiyor'),
                        "in_octets": i_item.get('in_octets'),
                        "out_octets": i_item.get('out_octets')
                    })
            if not interfaces:
                iface_error = {"message": "Ağ Arayüz verisi alınamadı veya ayrıştırılamadı. Hedef cihazda Ağ Arayüz OID'si desteklenmiyor olabilir.", "type": "warning"}
            print(f"DEBUG: Interfaces: {interfaces}")
            sys.stdout.flush()
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired, FileNotFoundError) as e:
            iface_error = {"message": f"Ağ Arayüz sorgusu hatası: {e}", "type": "danger"}
            print(f"ERROR: Ağ Arayüz sorgusu hatası: {e}")
            sys.stdout.flush()
        except Exception as e:
            iface_error = {"message": f"Ağ Arayüz verisi işlenirken hata: {e}", "type": "danger"}
            print(f"ERROR: Ağ Arayüz işleme hatası: {e}")
            sys.stdout.flush()

        # SNMP Sistem Bilgisi
        parsed_sysinfo = [] # Ayrıştırılmış sistem bilgisi
        try:
            # -On parametresi ile sayısal OID formatında çıktı alıyoruz
            cmd_sysinfo = ["snmpwalk", "-v2c", "-c", community, "-On", ip, "1.3.6.1.2.1.1"] # sys group
            print(f"DEBUG: SNMP Sistem Bilgisi komutu: {' '.join(cmd_sysinfo)}")
            sys.stdout.flush()
            sysinfo_result = subprocess.run(cmd_sysinfo, capture_output=True, text=True, timeout=10, check=True)
            raw_sysinfo_lines = [line for line in sysinfo_result.stdout.strip().splitlines() if line]
            
            if not raw_sysinfo_lines:
                sysinfo_error = {"message": "Sistem bilgisi verisi alınamadı.", "type": "warning"}
            else:
                # OID'leri daha okunabilir isimlere eşleme
                sysinfo_map = {
                    ".1.3.6.1.2.1.1.1.0": "Sistem Açıklaması", # sysDescr.0
                    ".1.3.6.1.2.1.1.2.0": "Sistem Nesne ID'si", # sysObjectID.0
                    ".1.3.6.1.2.1.1.3.0": "Sistem Çalışma Süresi", # sysUpTime.0
                    ".1.3.6.1.2.1.1.4.0": "Sistem İletişim Bilgisi", # sysContact.0
                    ".1.3.6.1.2.1.1.5.0": "Sistem Adı", # sysName.0
                    ".1.3.6.1.2.1.1.6.0": "Sistem Konumu", # sysLocation.0
                    ".1.3.6.1.2.1.1.7.0": "Sistem Servisleri", # sysServices.0
                }
                
                for line in raw_sysinfo_lines:
                    # Örnek satır: .1.3.6.1.2.1.1.1.0 = STRING: "Linux..."
                    # Hata düzeltildi: re.re.match -> re.match
                    match = re.match(r'(\.\d+(\.\d+)*)\s*=\s*(.+)', line) 
                    if match:
                        oid = match.group(1).strip()
                        value_raw = match.group(3).strip()
                        
                        display_name = sysinfo_map.get(oid, oid) # Eşlenmiş adı kullan, yoksa ham OID
                        
                        # Değeri tipine göre temizle ve formatla
                        if "STRING:" in value_raw:
                            value = value_raw.split("STRING:", 1)[-1].strip().strip('"')
                        elif "OID:" in value_raw:
                            value = value_raw.split("OID:", 1)[-1].strip()
                        elif "Timeticks:" in value_raw:
                            # Sadece formatlanmış zamanı al, örn: "1:13:59.42"
                            time_match = re.search(r'Timeticks: \(\d+\)\s*(.+)', value_raw)
                            value = time_match.group(1).strip() if time_match else value_raw
                        elif "INTEGER:" in value_raw:
                            value_match = re.search(r'INTEGER:\s*(\d+)', value_raw)
                            value = value_match.group(1) if value_match else value_raw
                        elif "Hex-STRING:" in value_raw: # MAC adresleri için
                            value = value_raw.split("Hex-STRING:", 1)[-1].strip().replace(" ", ":")
                        elif "IpAddress:" in value_raw:
                            value = value_raw.split("IpAddress:", 1)[-1].strip()
                        else:
                            value = value_raw # Fallback
                        
                        parsed_sysinfo.append({"name": display_name, "value": value})

            print(f"DEBUG: Parsed System Info: {parsed_sysinfo}")
            sys.stdout.flush()
        except subprocess.CalledProcessError as e:
            sysinfo_error = {"message": f"Sistem bilgisi sorgusu başarısız oldu: {e.stderr.strip()}", "type": "danger"}
            print(f"ERROR: Sistem bilgisi sorgusu hatası: {e}")
            sys.stdout.flush()
        except subprocess.TimeoutExpired:
            sysinfo_error = {"message": "Sistem bilgisi sorgusu zaman aşımına uğradı.", "type": "danger"}
            print("ERROR: Sistem bilgisi sorgusu zaman aşımı.")
            sys.stdout.flush()
        except FileNotFoundError:
            sysinfo_error = {"message": "SNMP komutu bulunamadı.", "type": "danger"}
            print("ERROR: SNMP komutu bulunamadı.")
            sys.stdout.flush()
        except Exception as e:
            sysinfo_error = {"message": f"Sistem bilgisi işlenirken hata: {e}", "type": "danger"}
            print(f"ERROR: Sistem bilgisi işleme hatası: {e}")
            sys.stdout.flush()

        # Uptime (Zaten parsed_sysinfo içinde de yer alacak ama ayrı bir değişken olarak da tutulabilir)
        try:
            uptime_ticks = _get_snmp_value(ip, community, OID_SYS_UPTIME, type_prefix="Timeticks")
            if uptime_ticks is None:
                uptime_error = {"message": "Çalışma süresi verisi alınamadı.", "type": "warning"}
            print(f"DEBUG: Uptime Ticks: {uptime_ticks}")
            sys.stdout.flush()
        except Exception as e:
            uptime_error = {"message": f"Çalışma süresi verisi işlenirken hata: {e}", "type": "danger"}
            print(f"ERROR: Uptime işleme hatası: {e}")
            sys.stdout.flush()

        # Temperature
        try:
            temperature = _get_snmp_value(ip, community, OID_TEMP_SENSOR, type_prefix="INTEGER")
            if temperature is None:
                temp_error = {"message": "Sıcaklık verisi alınamadı (OID bulunamadı/desteklenmiyor olabilir).", "type": "warning"}
            print(f"DEBUG: Sıcaklık: {temperature}")
            sys.stdout.flush()
        except Exception as e:
            temp_error = {"message": f"Sıcaklık verisi işlenirken hata: {e}", "type": "danger"}
            print(f"ERROR: Sıcaklık işleme hatası: {e}")
            sys.stdout.flush()

        # Established Connections
        try:
            cmd_tcp_conn = ["snmpwalk", "-v2c", "-c", community, ip, OID_TCP_CONN_STATE]
            print(f"DEBUG: TCP Bağlantı komutu: {' '.join(cmd_tcp_conn)}")
            sys.stdout.flush()
            tcp_conn_result = subprocess.run(cmd_tcp_conn, capture_output=True, text=True, timeout=10, check=False)
            print(f"DEBUG: TCP Bağlantı stdout: {tcp_conn_result.stdout.strip()}")
            print(f"DEBUG: TCP Bağlantı stderr: {tcp_conn_result.stderr.strip()}")
            sys.stdout.flush()
            established_count = 0
            for line in tcp_conn_result.stdout.strip().splitlines():
                # TCP connection state OID'leri genellikle 1.3.6.1.2.1.6.13.1.1.X formatındadır.
                # Durum değeri 1 (closed) ile 12 (timeWait) arasında değişir.
                # Established (kurulmuş) bağlantı durumu genellikle 5'tir.
                if "INTEGER: 5" in line:
                    established_count += 1
            established_connections = established_count
            if established_connections == 0 and "No Such Instance" in tcp_conn_result.stdout:
                 conn_error = {"message": "TCP bağlantı verisi alınamadı.", "type": "warning"}
            print(f"DEBUG: Kurulmuş TCP Bağlantıları: {established_connections}")
            sys.stdout.flush()
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired, FileNotFoundError) as e:
            conn_error = {"message": f"TCP bağlantı sorgusu hatası: {e}", "type": "danger"}
            print(f"ERROR: TCP bağlantı sorgusu hatası: {e}")
            sys.stdout.flush()
        except Exception as e:
            conn_error = {"message": f"TCP bağlantı verisi işlenirken hata: {e}", "type": "danger"}
            print(f"ERROR: TCP bağlantı işleme hatası: {e}")
            sys.stdout.flush()


        return render_template("snmp_result.html", 
                               ip=ip, 
                               community=community,
                               cpu_values=cpu_values, 
                               total_ram_kbytes=total_ram_kbytes,
                               ram_kbytes=ram_kbytes,
                               ram_used_percent=ram_used_percent,
                               disks=disks,
                               interfaces=interfaces,
                               sysinfo_lines=parsed_sysinfo, # Artık ayrıştırılmış veriyi gönderiyoruz
                               uptime_ticks=uptime_ticks,
                               temperature=temperature,
                               established_connections=established_connections,
                               cpu_alert=None,
                               ram_alert=None,
                               general_error=general_error,
                               cpu_error=cpu_error,
                               ram_error=ram_error,
                               disk_error=disk_error,
                               iface_error=iface_error,
                               sysinfo_error=sysinfo_error,
                               uptime_error=uptime_error,
                               temp_error=temp_error,
                               conn_error=conn_error
                               )

    @app.route("/get_snmp_realtime")
    def get_snmp_realtime():
        """SNMP verilerini gerçek zamanlı grafikler için döndürür (AJAX)."""
        ip = request.args.get("ip")
        community = request.args.get("community", "public")

        cpu_loads = []
        ram_used_percent = None
        uptime_ticks = None
        temperature = None
        established_connections = None
        
        # CPU
        try:
            # -On parametresi eklendi
            cmd_cpu = ["snmpwalk", "-v2c", "-c", community, "-On", ip, OID_CPU_LOAD]
            print(f"DEBUG (realtime CPU): Komut: {' '.join(cmd_cpu)}")
            sys.stdout.flush()
            cpu_result = subprocess.run(cmd_cpu, capture_output=True, text=True, timeout=5, check=False)
            print(f"DEBUG (realtime CPU): stdout: {cpu_result.stdout.strip()}")
            print(f"DEBUG (realtime CPU): stderr: {cpu_result.stderr.strip()}")
            sys.stdout.flush()
            for line in cpu_result.stdout.strip().splitlines():
                match = re.search(r'INTEGER:\s*(\d+)', line)
                if match:
                    try:
                        load = int(match.group(1))
                        cpu_loads.append(load)
                    except ValueError:
                        pass
        except Exception as e:
            print(f"ERROR (realtime CPU): {e}")
            sys.stdout.flush()
            pass

        # RAM
        try:
            total_ram_kbytes = _get_snmp_value(ip, community, OID_MEMORY_SIZE, type_prefix="INTEGER")
            if total_ram_kbytes is not None and total_ram_kbytes > 0:
                hr_storage_column_oids = {
                    '2': 'type',
                    '4': 'allocation_units',
                    '6': 'used'
                }
                storage_data = _snmpwalk_parse_table(ip, community, OID_HR_STORAGE_TABLE, hr_storage_column_oids, timeout=5)
                ram_used_kbytes_realtime = 0
                for idx, item in storage_data.items():
                    if item.get('type') == 'RAM':
                        if 'allocation_units' in item and 'used' in item:
                            ram_used_kbytes_realtime = (item['used'] * item['allocation_units']) / 1024
                            break
                if ram_used_kbytes_realtime is not None and total_ram_kbytes > 0:
                    ram_used_percent = (ram_used_kbytes_realtime / total_ram_kbytes) * 100
        except Exception as e:
            print(f"ERROR (realtime RAM): {e}")
            sys.stdout.flush()
            pass
        
        # Uptime
        try:
            uptime_ticks = _get_snmp_value(ip, community, OID_SYS_UPTIME, type_prefix="Timeticks")
        except Exception as e:
            print(f"ERROR (realtime Uptime): {e}")
            sys.stdout.flush()
            pass

        # Temperature
        try:
            temperature = _get_snmp_value(ip, community, OID_TEMP_SENSOR, type_prefix="INTEGER")
        except Exception as e:
            print(f"ERROR (realtime Temp): {e}")
            sys.stdout.flush()
            pass

        # Established Connections
        try:
            cmd_tcp_conn = ["snmpwalk", "-v2c", "-c", community, ip, OID_TCP_CONN_STATE]
            print(f"DEBUG: TCP Bağlantı komutu: {' '.join(cmd_tcp_conn)}")
            sys.stdout.flush()
            tcp_conn_result = subprocess.run(cmd_tcp_conn, capture_output=True, text=True, timeout=5, check=False)
            print(f"DEBUG: TCP Bağlantı stdout: {tcp_conn_result.stdout.strip()}")
            print(f"DEBUG: TCP Bağlantı stderr: {tcp_conn_result.stderr.strip()}")
            sys.stdout.flush()
            established_count = 0
            for line in tcp_conn_result.stdout.strip().splitlines():
                if "INTEGER: 5" in line:
                    established_count += 1
            established_connections = established_count
        except Exception as e:
            print(f"ERROR: TCP Bağlantı: {e}")
            sys.stdout.flush()
            pass

        return jsonify({
            "cpu": cpu_loads,
            "ram": ram_used_percent,
            "uptime_ticks": uptime_ticks,
            "temperature": temperature,
            "established_connections": established_connections
        })


    @app.route("/get_interfaces")
    def get_interfaces():
        """SNMP ile ağ arayüzlerini döndürür (AJAX için)."""
        ip = request.args.get("ip")
        community = request.args.get("community", "public")
        print(f"DEBUG: Arayüzler isteniyor: IP={ip}, Community={community}")
        sys.stdout.flush()
        try:
            # ifDescr OID'sini kullanarak arayüz açıklamalarını al
            cmd = ["snmpwalk", "-v2c", "-c", community, ip, OID_IF_DESCR] # ifDescr OID
            print(f"DEBUG: get_interfaces komutu: {' '.join(cmd)}")
            sys.stdout.flush()
            # check=False yaparak komut hata verse bile çıktıyı alıyoruz
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10, check=False) 
            print(f"DEBUG: get_interfaces stdout:\n{result.stdout.strip()}")
            print(f"DEBUG: get_interfaces stderr:\n{result.stderr.strip()}")
            sys.stdout.flush()

            lines = [line for line in result.stdout.strip().splitlines() if line]
            interfaces_list = []
            for line in lines:
                # Örnek satır: iso.3.6.1.2.1.2.2.1.2.1 = STRING: "lo"
                if " = " in line and "STRING:" in line:
                    try:
                        oid_part, value_part = line.split(" = ", 1) # Sadece ilk " = " ile böl
                        
                        # OID kısmından indeksi çıkar (örn: iso.3.6.1.2.1.2.2.1.2.1 -> 1)
                        oid_match = re.search(r'\.(\d+)$', oid_part.strip())
                        if not oid_match:
                            print(f"WARNING: OID'den indeks çıkarılamadı: {oid_part}")
                            sys.stdout.flush()
                            continue # İndeks bulunamazsa bu satırı atla

                        idx = oid_match.group(1)
                        
                        # Değer kısmından arayüz adını çıkar (örn: STRING: "lo" -> lo)
                        name = value_part.split("STRING:", 1)[-1].strip().strip('"')
                        
                        if name: # Ad boş değilse listeye ekle
                            interfaces_list.append({"index": idx, "descr": name})
                        else:
                            print(f"WARNING: Arayüz adı boş bulundu: {line}")
                            sys.stdout.flush()

                    except Exception as parse_e:
                        print(f"ERROR: Satır ayrıştırılırken hata '{line}': {parse_e}")
                        sys.stdout.flush()
                        continue # Bir satır hata verirse diğerlerine devam et
            print(f"DEBUG: Arayüzler bulundu (parsed): {interfaces_list}") # Ayrıştırılmış listeyi logla
            sys.stdout.flush()
            return jsonify({"interfaces": interfaces_list})
        except Exception as e: # Daha genel bir hata yakalama
            print(f"ERROR: Arayüzler alınırken beklenmeyen hata: {e}")
            sys.stdout.flush()
            return jsonify({"error": f"Arayüzler alınırken hata: {e}"})

    @app.route("/get_speed_data")
    def get_speed_data():
        """Gerçek zamanlı trafik verilerini döndürür (AJAX için)."""
        ip = request.args.get("ip")
        community = request.args.get("community", "public")
        iface_index = request.args.get("iface")

        if not ip or not iface_index:
            return jsonify({"error": "IP adresi veya arayüz indeksi eksik."})

        print(f"DEBUG: Hız verisi isteniyor: IP={ip}, Iface={iface_index}")
        sys.stdout.flush()
        try:
            # ifInOctets ve ifOutOctets OID'lerini belirli arayüz için al
            in_octets_oid = f"{OID_IF_IN_OCTETS}.{iface_index}"
            out_octets_oid = f"{OID_IF_OUT_OCTETS}.{iface_index}"

            in_octets = _get_snmp_value(ip, community, in_octets_oid, type_prefix="Counter32") # Counter32 olarak belirtildi
            out_octets = _get_snmp_value(ip, community, out_octets_oid, type_prefix="Counter32") # Counter32 olarak belirtildi

            print(f"DEBUG: In Octets: {in_octets}, Out Octets: {out_octets}")
            sys.stdout.flush()

            if in_octets is None or out_octets is None:
                return jsonify({"error": "Trafik verisi alınamadı. Arayüz indeksi yanlış olabilir veya cihaz yanıt vermiyor."})
            
            return jsonify({"in_octets": in_octets, "out_octets": out_octets})

        except Exception as e:
            print(f"ERROR: Trafik verisi alınırken hata: {e}")
            sys.stdout.flush()
            return jsonify({"error": f"Trafik verisi alınırken hata: {e}"})

    @app.route('/speedtest')
    def speedtest():
        """Gerçek zamanlı speedtest sayfasını render eder."""
        return render_template('speedtest.html')

    @app.route('/run_internet_speedtest')
    def run_internet_speedtest():
        """
        Internet hız testini çalıştırır ve sonuçları JSON olarak döndürür.
        Bu fonksiyon app.py'den _run_internet_speedtest yardımcı fonksiyonunu çağırır.
        """
        result = _run_internet_speedtest()
        return jsonify(result) 


    @app.route("/kayitlar")
    def kayitlar():
        """Tarama kayıtlarını gösterir."""
        rows = db.get_recent_scan_records()
        return render_template("kayitlar.html", rows=rows)

    @app.route("/kayitlar/sil", methods=["POST"])
    def clear_records():
        """Tüm tarama kayıtlarını siler."""
        db.clear_scan_records()
        return redirect(url_for("kayitlar"))

    @app.route("/cihazlar")
    def cihazlar():
        """Cihaz yönetimi sayfasını gösterir."""
        rows = db.get_all_devices() # Eşik değerleri de dahil olmak üzere tüm cihazları çek
        return render_template("cihazlar.html", rows=rows)

    @app.route("/cihazlar", methods=["POST"])
    def add_device():
        """Yeni cihaz ekler veya mevcut cihazı günceller."""
        isim = request.form["isim"]
        ip = request.form["ip"]
        community = request.form.get("community", "public")
        
        # Formdan eşik değerlerini al, yoksa varsayılanları kullan
        # float'a çevirirken hata oluşursa varsayılan değerleri kullan
        try:
            cpu_threshold = float(request.form.get("cpu_threshold", 80.0))
            ram_threshold = float(request.form.get("ram_threshold", 80.0))
            disk_threshold = float(request.form.get("disk_threshold", 90.0))
        except ValueError:
            return "Hata: Eşik değerleri geçerli sayılar olmalıdır. Lütfen sayısal bir değer girin.", 400

        device_id = request.form.get("device_id") # Eğer düzenleme ise device_id gelir

        try:
            if device_id:
                # Cihazı güncelle
                db.update_device(int(device_id), isim, ip, community, cpu_threshold, ram_threshold, disk_threshold)
            else:
                # Yeni cihaz ekle
                db.add_device(isim, ip, community, cpu_threshold, ram_threshold, disk_threshold)
            return redirect(url_for("cihazlar"))
        except Exception as e:
            print(f"ERROR: Cihaz ekleme/güncelleme hatası: {e}")
            return f"Beklenmeyen bir hata oluştu: {e}", 500


    @app.route("/cihazlar/sil/<int:device_id>", methods=["POST"])
    def delete_device(device_id):
        """Cihazı siler."""
        db.delete_device(device_id)
        return redirect(url_for("cihazlar"))

    @app.route("/alerts")
    def alerts():
        """Aktif uyarıları gösterir."""
        active_alerts = db.get_active_alerts() # Sadece aktif uyarıları çek
        return render_template("alerts.html", alerts=active_alerts)

    @app.route("/alerts/history")
    def alerts_history():
        """Tüm uyarıları (aktif ve çözülmüş) gösterir."""
        all_alerts = db.get_all_alerts() # Tüm uyarıları çek
        return render_template("alerts_history.html", alerts=all_alerts)
