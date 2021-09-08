import ipaddress

ip_addr = '10.3.102.10'
snmp_community = 'public'
out_file = 'c:\\config.txt'

# Чтобы всё это заработало - нужно скомпилировать MIB-файл от длинка 1210.
# Называется он DLINK-DGS-1210-F1-SERIES-MIB, взять его можно из фтп длинка
# https://ftp.dlink.ru/pub/Switch/DGS-1210-52/SNMP/DGS-1210-FX-Series-6-00-011.mib
# После этого его нужно скомпилить - под виндой достаточно скинуть этот файл в пустую папку и запустить
# python venv\scripts\mibdump.py --mib-source file://c:/new_folder DLINK-DGS-1210-F1-SERIES-MIB
# После этого всё будет работать.

from pysnmp.hlapi import *
import pickle


# Текстовое представление списка вланов
def vlan_array_to_str(arr):
    if len(arr) == 0:
        return ''
    result = ''
    dia = []
    for elem in arr:
        if len(dia) == 0:
            dia.append(elem)
        elif len(dia) > 0 and dia[len(dia) - 1] == elem - 1:
            dia.append(elem)
        else:
            if len(dia) > 1:
                result = result + ', ' + "{} to {}".format(min(dia), max(dia))
            else:
                result = result + ', ' + str(dia[0])
            dia = [elem]
    if len(dia) > 1:
        result = result + ', ' + "{} to {}".format(min(dia), max(dia))
    else:
        result = result + ', ' + str(dia[0])
    result = result.strip(',').strip(' ')
    return result


# Побитный итератор для расшифровки SNMP от D-Link (PortList)
def iter_bit(number):
    bit = 1
    idx = 7
    while number >= bit:
        if number & bit:
            yield idx
        idx -= 1
        bit <<= 1


# Итератор по значениям SNMP
def iter_snmp_table(mib, object_type_list, is_table=True):
    args = []
    for arg in object_type_list:
        # ObjectIdentity иницилазириуется по-разному для таблиц и для отдельных значений
        if is_table:
            args.append(ObjectType(ObjectIdentity(mib, arg)))
        else:
            args.append(ObjectType(ObjectIdentity(mib, arg, 0)))
    # Если итерируем таблицы - используем next, иначе get
    if is_table:
        cmd = nextCmd
    else:
        cmd = getCmd
    for errorIndication, errorStatus, errorIndex, varBinds in cmd(
            SnmpEngine(),
            CommunityData(snmp_community),
            UdpTransportTarget((ip_addr, 161)),
            ContextData(),
            *(args),
            lookupMib=True,
            lexicographicMode=False):
        if errorIndication:
            print(errorIndication)
            break

        elif errorStatus:
            print('%s at %s' % (errorStatus.prettyPrint(),
                                errorIndex and varBinds[int(errorIndex) - 1][0] or '?'))
            break
        else:
            for varBind in varBinds:
                yield varBind[0], varBind[1]


# Парсит SNMP таблицу и вызывает лямбда-обработчики для каждого значения
def parse_snmp(mib, handler_list, is_table=True):
    result = {}
    object_type_list = [x for x in handler_list]
    print("Getting {} from MIB {}...".format(', '.join(object_type_list), mib), end='')
    for var_name, var_value in iter_snmp_table(
            mib=mib,
            object_type_list=object_type_list,
            is_table=is_table
    ):
        # Вытаскиваем цифровой OID
        oid = str(var_name.getOid())
        # Получаем номер столбца в таблице SNMP - это последнее значение в OID
        row = int(oid[str(oid).rfind('.') + 1:])
        if is_table and row not in result:
            result[row] = {}
        # Имя столбца
        name = var_name.getMibSymbol()[1]
        # Запускаем обработчики
        if name in handler_list:
            handler = handler_list[name][1]
            field_name = handler_list[name][0]
            # Если field_name is None - тогда используем Name из MIB
            field_name = name if field_name is None else field_name
            if is_table:
                result[row][field_name] = handler(var_name, var_value)
            else:
                result[field_name] = handler(var_name, var_value)
        else:
            print("Unknown field: {}".format(name))
            exit(-1)
    print('done!')

    # Если запрашивали таблицу, то и возвращаем таблицу
    return result


# Лямбда для обработки строк SNMP
def snmp_string(name, value):
    return str(value.prettyPrint())


# Лябмда для обработки целочисленных значений SNMP
def snmp_int(name, value):
    return int(value.prettyPrint())


# Лябмда для обработки IP-адресов SNMP
def snmp_ipaddr(name, value):
    if len(value) == 0:
        return None
    elif len(value) == 4:
        return ipaddress.IPv4Address('.'.join(str(octet) for octet in value))
    else:
        return ipaddress.IPv6Address(value)


# Лямбда для обработки PortList, возвращает массив со списком номеров портов
def snmp_portlist(name, value):
    result = []
    for octet_index, octet in enumerate(value):
        for bit in iter_bit(octet):
            result.append(octet_index * 8 + bit + 1)
    return result


def get_vlan_info():
    return parse_snmp(
        mib='DLINK-DGS-1210-F1-SERIES-MIB',
        handler_list={
            'dot1qVlanName': ['comment', snmp_string],
            'dot1qVlanEgressPorts': ['permitted_ports', snmp_portlist],
            'dot1qVlanUntaggedPorts': ['untagged_ports', snmp_portlist]
        }
    )


def get_pvid_info():
    return parse_snmp(
        mib='DLINK-DGS-1210-F1-SERIES-MIB',
        handler_list={
            'dot1qVlanPvid': ['pvid', snmp_int],
        }
    )


def get_port_description():
    return parse_snmp(
        mib='DLINK-DGS-1210-F1-SERIES-MIB',
        handler_list={
            'sysPortDescIndex': ['ifIndex', snmp_int],
            'sysPortDescString': ['ifDesc', snmp_string],
        }
    )


def get_if_mib():
    return parse_snmp(
        mib='IF-MIB',
        handler_list={
            'ifType': [None, snmp_string],
            'ifAdminStatus': [None, snmp_string],
        }
    )


def get_media_type():
    return parse_snmp(
        mib='DLINK-DGS-1210-F1-SERIES-MIB',
        handler_list={
            'sysPortCtrlSpeed': [None, snmp_string],
            'sysPortCtrlOperStatus': [None, snmp_string],
            'sysPortCtrlMDI': [None, snmp_string],
            'sysPortCtrlFlowControl': [None, snmp_string],
            'sysPortCtrlFlowControlOper': [None, snmp_string],
            'sysPortCtrlType': [None, snmp_string],
        }
    )


def get_lacp_port_activity():
    return parse_snmp(
        mib='DLINK-DGS-1210-F1-SERIES-MIB',
        handler_list={
            'laPortControlIndex': [None, snmp_string],
            'laPortActorActivity': [None, snmp_string],
            'laPortActorTimeout': [None, snmp_string],
        }
    )


def get_lacp_groups():
    return parse_snmp(
        mib='DLINK-DGS-1210-F1-SERIES-MIB',
        handler_list={
            'laPortChannelIfIndex': [None, snmp_int],
            'laPortChannelMemberList': [None, snmp_portlist],
            'laPortChannelMode': [None, snmp_string],
        }
    )


def get_system_info():
    return parse_snmp(
        mib='DLINK-DGS-1210-F1-SERIES-MIB',
        handler_list={
            'sysSwitchName': [None, snmp_string],
            'sysHardwareVersion': [None, snmp_string],
            'sysFirmwareVersion': [None, snmp_string],
            'sysLoginTimeoutInterval': [None, snmp_int],
            'sysLocationName': [None, snmp_string],
            'sysSafeGuardEnable': [None, snmp_string],
            'sysJumboFrameEnable': [None, snmp_string],
        },
        is_table=False
    )


def get_sntp_info():
    return parse_snmp(
        mib='DLINK-DGS-1210-F1-SERIES-MIB',
        handler_list={
            'sysSNTPFirstServer': [None, snmp_ipaddr],
            'sysSNTPFirstType': [None, snmp_string],
            'sysSNTPFirstInterfaceName': [None, snmp_string],
            'sysSNTPSecondServer': [None, snmp_ipaddr],
            'sysSNTPSecondType': [None, snmp_string],
            'sysSNTPSecondInterfaceName': [None, snmp_string],
            'sysSNTPPollInterval': [None, snmp_int],
            'sysSNTPState': [None, snmp_string],
        },
        is_table=False
    )


debug = False

# Открываем файл и пишем в него баннер
file_obj = open(out_file, 'w', encoding="utf8")
print("# Configuration from {}, snmp_community {}\n".format(ip_addr, snmp_community), file=file_obj)

# Получаем данные
if not debug:
    sntp_info = get_sntp_info()
    vlan_info = get_vlan_info()
    pvid_info = get_pvid_info()
    port_desc_info = get_port_description()
    if_mb_info = get_if_mib()
    phy_media_info = get_media_type()
    lacp_info = get_lacp_groups()
    system_info = get_system_info()

    with open('c:\\data.pickle', 'wb') as f:
        pickle.dump(
            (vlan_info, pvid_info, port_desc_info, if_mb_info, phy_media_info, lacp_info, system_info, sntp_info), f)

else:
    with open('c:\\data.pickle', 'rb') as f:
        (vlan_info, pvid_info, port_desc_info, if_mb_info, phy_media_info, lacp_info, system_info,
         sntp_info) = pickle.load(f)

# Отступ
tab = "  "
block_delimiter = "!\n"

# Информация о коммутаторе
print("# Hardware version:", system_info['sysHardwareVersion'], file=file_obj)
print("# Firmware version:", system_info['sysFirmwareVersion'], file=file_obj)
print("\n\n", file=file_obj)

print("SYSNAME", system_info['sysSwitchName'], file=file_obj)
print("LOCATION", system_info['sysLocationName'], file=file_obj)
print("\n\n", file=file_obj)
print("login-timeout", system_info['sysLoginTimeoutInterval'], file=file_obj)
print("safeguard-engine", system_info['sysSafeGuardEnable'], file=file_obj)
print("jumbo-frame", system_info['sysJumboFrameEnable'], file=file_obj)
print("\n\n", file=file_obj)

# Перебираем все LACP линки
for port_channel_id in lacp_info:
    # Пропускаем пустые группы
    lacp_group = lacp_info[port_channel_id]
    if lacp_group['laPortChannelMode'] == 'disable':
        continue

    # Генерируем красивое имя
    print("interface Port-channel{}".format(lacp_group['laPortChannelIfIndex']), file=file_obj)
    # Сортируем список портов для красивого вывода
    member_ports = lacp_group['laPortChannelMemberList']
    member_ports.sort()
    print(tab, "# Member ports: {}".format(vlan_array_to_str(member_ports)), file=file_obj)
    print(tab, "mode {}".format(lacp_group['laPortChannelMode']), file=file_obj)
    print(block_delimiter, file=file_obj)

# Перебираем все полученные интерфейсы
for phy_int_id in phy_media_info:
    phy_int = phy_media_info[phy_int_id]

    # Генерируем красивое имя интерфейса
    replacement_arr = [
        ['gigabit', 'Gigabit'],
        ['fast', 'Fast'],
        ['ethernet', 'Ethernet'],
    ]
    int_name = phy_int['sysPortCtrlType']
    for repl in replacement_arr:
        int_name = int_name.replace(repl[0], repl[1])

    print("interface {}0/{}".format(int_name, phy_int_id), file=file_obj)

    # описание
    if port_desc_info[phy_int_id]['ifDesc'] != '':
        print(tab, "description {}".format(port_desc_info[phy_int_id]['ifDesc']), file=file_obj)

    # Получаем список разрешенных и растегированных вланов
    permitted_vlans = []
    untagged_vlans = []
    for vlan_id in vlan_info:
        if phy_int_id in vlan_info[vlan_id]['permitted_ports']:
            permitted_vlans.append(vlan_id)
        if phy_int_id in vlan_info[vlan_id]['untagged_ports']:
            untagged_vlans.append(vlan_id)

    # Получаем PVID
    pvid_vlan = pvid_info[phy_int_id]['pvid']

    # Разбираемся с типом порта (access\trunk)
    # 1) у доступа разрешен только один влан
    # 2) он находится в антеге
    # 3) он находится в PVID
    # 4) иначе - это транк
    if len(permitted_vlans) == 1 and \
            len(untagged_vlans) == 1 and \
            permitted_vlans[0] == untagged_vlans[0] and \
            permitted_vlans[0] == pvid_vlan:
        is_access = True
    else:
        is_access = False

    if is_access:
        print(tab, 'switchport mode access', file=file_obj)
        print(tab, 'switchport access vlan {}'.format(pvid_vlan), file=file_obj)
    else:
        print(tab, 'switchport mode trunk', file=file_obj)
        # Теперь нам нужно разобраться, есть ли у нас native vlan
        # Проверяем по количеству растегированных вланов. если их нет - то и нативного влана нет.
        permitted_vlans_str = vlan_array_to_str(permitted_vlans)
        print(tab, 'switchport trunk allowed vlan {}'.format(permitted_vlans_str), file=file_obj)
        if len(untagged_vlans) == 0:
            # транк без нативного порта
            pass
        elif len(untagged_vlans) == 1:
            # Транк с нативным вланом
            # PVID VLAN должен быть антегнут
            if untagged_vlans[0] != pvid_vlan:
                print("Untagged VLAN on ifIndex does not match PVID VLAN {}, {}".format(phy_int_id, untagged_vlans))
                exit(-1)
            print(tab, 'switchport trunk native vlan {}'.format(pvid_vlan), file=file_obj)
        else:
            # Больше одного антег влана, так быть не должно!
            print("More then one untagged VLAN on ifIndex {}, {}".format(phy_int_id, untagged_vlans))
            exit(-1)

    # Проверяем, входит ли порт в группу port-channel
    for port_channel_id in lacp_info:
        # Пропускаем пустые группы
        lacp_group = lacp_info[port_channel_id]
        if lacp_group['laPortChannelMode'] == 'disable':
            continue
        if phy_int_id in lacp_group['laPortChannelMemberList']:
            print(tab, 'channel-group {}'.format(lacp_group['laPortChannelIfIndex']), file=file_obj)
    # Разделитель описаний портов
    print(block_delimiter, file=file_obj)

# SNTP
print("\n")
# Первый сервер
print("sntp first-server {} type {}".format(
    sntp_info['sysSNTPFirstServer'],
    sntp_info['sysSNTPFirstType']
), file=file_obj)

# Второй сервер
print("sntp second-server {} type {}".format(
    sntp_info['sysSNTPSecondServer'],
    sntp_info['sysSNTPSecondType']
), file=file_obj)

# Настройки sntp
print("sntp poll-interval", sntp_info['sysSNTPPollInterval'], file=file_obj)
print("sntp state", sntp_info['sysSNTPState'], file=file_obj)

file_obj.close()
