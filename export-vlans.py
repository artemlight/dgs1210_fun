ip_addr = '10.3.102.10'
snmp_community = 'public'

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
def iter_snmp_table(mib, object_type_list):
    args = []
    for arg in object_type_list:
        args.append(ObjectType(ObjectIdentity(mib, arg)))
    for errorIndication, errorStatus, errorIndex, varBinds in nextCmd(
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
def parse_snmp_table(mib, handler_list):
    result = {}
    object_type_list = [x for x in handler_list]
    print("Getting {} from MIB {}...".format(', '.join(object_type_list), mib), end='')
    for var_name, var_value in iter_snmp_table(
            mib=mib,
            object_type_list=object_type_list
    ):
        # Вытаскиваем цифровой OID
        oid = str(var_name.getOid())
        # Получаем номер столбца в таблице SNMP - это последнее значение в OID
        row = int(oid[str(oid).rfind('.') + 1:])
        if row not in result:
            result[row] = {}
        # Имя столбца
        name = var_name.getMibSymbol()[1]
        # Запускаем обработчики
        if name in handler_list:
            handler = handler_list[name][1]
            field_name = handler_list[name][0]
            # Если field_name is None - тогда используем Name из MIB
            field_name = name if field_name is None else field_name
            result[row][field_name] = handler(var_name, var_value)
        else:
            print("Unknown field: {}".format(name))
            exit(-1)
    print('done!')
    return result


# Лямбда для обработки строк SNMP
def snmp_string(name, value):
    return str(value.prettyPrint())


# Лябмда для обработки целочисленных значений SNMP
def snmp_int(name, value):
    return int(value.prettyPrint())


# Лямбда для обработки PortList, возвращает массив со списком номеров портов
def snmp_portlist(name, value):
    result = []
    for octet_index, octet in enumerate(value):
        for bit in iter_bit(octet):
            result.append(octet_index * 8 + bit + 1)
    return result


def get_vlan_info():
    return parse_snmp_table(
        mib='DLINK-DGS-1210-F1-SERIES-MIB',
        handler_list={
            'dot1qVlanName': ['comment', snmp_string],
            'dot1qVlanEgressPorts': ['permitted_ports', snmp_portlist],
            'dot1qVlanUntaggedPorts': ['untagged_ports', snmp_portlist]
        }
    )


def get_pvid_info():
    return parse_snmp_table(
        mib='DLINK-DGS-1210-F1-SERIES-MIB',
        handler_list={
            'dot1qVlanPvid': ['pvid', snmp_int],
        }
    )


def get_port_description():
    return parse_snmp_table(
        mib='DLINK-DGS-1210-F1-SERIES-MIB',
        handler_list={
            'sysPortDescIndex': ['ifIndex', snmp_int],
            'sysPortDescString': ['ifDesc', snmp_string],
        }
    )


def get_if_mib():
    return parse_snmp_table(
        mib='IF-MIB',
        handler_list={
            'ifType': [None, snmp_string],
            'ifAdminStatus': [None, snmp_string],
        }
    )


def get_media_type():
    return parse_snmp_table(
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
    return parse_snmp_table(
        mib='DLINK-DGS-1210-F1-SERIES-MIB',
        handler_list={
            'laPortControlIndex': [None, snmp_string],
            'laPortActorActivity': [None, snmp_string],
            'laPortActorTimeout': [None, snmp_string],
        }
    )


def get_lacp_groups():
    return parse_snmp_table(
        mib='DLINK-DGS-1210-F1-SERIES-MIB',
        handler_list={
            'laPortChannelIfIndex': [None, snmp_int],
            'laPortChannelMemberList': [None, snmp_portlist],
            'laPortChannelMode': [None, snmp_string],
        }
    )


debug = True

# Получаем данные
if not debug:
    vlan_info = get_vlan_info()
    pvid_info = get_pvid_info()
    port_desc_info = get_port_description()
    if_mb_info = get_if_mib()
    phy_media_info = get_media_type()
    lacp_info = get_lacp_groups()

    with open('c:\\data.pickle', 'wb') as f:
        pickle.dump((vlan_info, pvid_info, port_desc_info, if_mb_info, phy_media_info, lacp_info), f)

else:
    with open('c:\\data.pickle', 'rb') as f:
        (vlan_info, pvid_info, port_desc_info, if_mb_info, phy_media_info, lacp_info) = pickle.load(f)

# Отступ
tab = "  "
block_delimiter = "!\n"

# Перебираем все LACP линки
for port_channel_id in lacp_info:
    # Пропускаем пустые группы
    lacp_group = lacp_info[port_channel_id]
    if lacp_group['laPortChannelMode'] == 'disable':
        continue

    # Генерируем красивое имя
    print("interface Port-channel{}".format(lacp_group['laPortChannelIfIndex']))
    # Сортируем список портов для красивого вывода
    member_ports = lacp_group['laPortChannelMemberList']
    member_ports.sort()
    print(tab, "# Member ports: {}".format(vlan_array_to_str(member_ports)))
    print(tab, "mode {}".format(lacp_group['laPortChannelMode']))
    print(block_delimiter)

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

    print("interface {}0/{}".format(int_name, phy_int_id))

    # описание
    if port_desc_info[phy_int_id]['ifDesc'] != '':
        print(tab, "description {}".format(port_desc_info[phy_int_id]['ifDesc']))

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
        print(tab, 'switchport mode access')
        print(tab, 'switchport access vlan {}'.format(pvid_vlan))
    else:
        print(tab, 'switchport mode trunk')
        # Теперь нам нужно разобраться, есть ли у нас native vlan
        # Проверяем по количеству растегированных вланов. если их нет - то и нативного влана нет.
        permitted_vlans_str = vlan_array_to_str(permitted_vlans)
        print(tab, 'switchport trunk allowed vlan {}'.format(permitted_vlans_str))
        if len(untagged_vlans) == 0:
            # транк без нативного порта
            pass
        elif len(untagged_vlans) == 1:
            # Транк с нативным вланом
            # PVID VLAN должен быть антегнут
            if untagged_vlans[0] != pvid_vlan:
                print("Untagged VLAN on ifIndex does not match PVID VLAN {}, {}".format(phy_int_id, untagged_vlans))
                exit(-1)
            print(tab, 'switchport trunk native vlan {}'.format(pvid_vlan))
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
            print(tab, 'channel-group {}'.format(lacp_group['laPortChannelIfIndex']))
    # Разделитель описаний портов
    print(block_delimiter)
