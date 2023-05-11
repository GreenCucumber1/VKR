import pandas as pd
import numpy as np
import bnlearn as bn
import streamlit as st

model_bin = bn.load(filepath='final_bin')
model_mul012 = bn.load(filepath='final_mul012345')
model_mul01234 = bn.load(filepath='final_mul01234567')
df = pd.read_csv('df_for_func.csv')



protocol = {'tcp':2,'udp':3,'icmp':1}
ser = {'http': 23, 'private': 45, 'domain_u': 12, 'smtp': 49, 'ftp_data': 20, 'eco_i': 14, 'telnet': 55, 'other': 41, 'ecr_i': 15, 'ftp': 19, 'finger': 18, 'pop_3': 43,
 'auth': 4, 'imap4': 25, 'Z39_50': 3, 'bgp': 5, 'iso_tsap': 26, 'uucp': 58, 'whois': 61, 'uucp_path': 59, 'time': 56, 'courier': 6, 'vmnet': 60, 'nnsp': 38, 'domain': 11,
 'urp_i': 57, 'ctf': 8, 'csnet_ns': 7, 'supdup': 53, 'discard': 10, 'gopher': 21, 'daytime': 9, 'sunrpc': 52, 'http_443': 24, 'systat': 54, 'link': 30, 'name': 33, 'hostnames': 22,
 'exec': 17, 'efs': 16, 'mtp': 32, 'echo': 13, 'login': 31, 'klogin': 27, 'ldap': 29, 'netbios_dgm': 34, 'netstat': 37, 'netbios_ns': 35, 'netbios_ssn': 36, 'ssh': 51,
 'nntp': 39, 'kshell': 28, 'sql_net': 50, 'IRC': 1, 'ntp_u': 40, 'pop_2': 42, 'remote_job': 46, 'rje': 47, 'shell': 48, 'printer': 44, 'X11': 2}
fl = {'SF':10,'S0':6,'REJ':2,'RSTR':5,'RSTO':3,'S1':7,'SH':11,'S3':9,'S2':8,'RSTOS0':4,'OTH':1}
attacks_01={'normal':1,'anomaly':0}
attacks = {'normal': 9, 'neptune': 7, 'ipsweep': 4, 'satan': 15, 'smurf': 16, 'portsweep': 12, 'nmap': 8, 'guess_passwd': 2, 'back': 1, 'mscan': 6, 'warezmaster': 21,
 'warezclient': 20,'teardrop': 19,'apache2': 0,'processtable': 13,'mailbomb': 5, 'snmpguess': 18, 'other': 10, 'saint': 14, 'pod': 11, 'snmpgetattack': 17, 'httptunnel': 3}
attacks_5 = {'normal':1,'dos':0,'probe':3,'other':2,'r2l':4,'u2r':5}


st.sidebar.title("Menu")
app_mode = st.sidebar.selectbox('Select',['Main','Prediction'])


    
if app_mode == "Prediction":
    classification_type = st.sidebar.radio('Выберите тип анализа', ['Биномиальный','Определение катерогии атаки', 'Определение типа атаки'])
    st.subheader('Вам необходимо выбрать тип классификации, а также внести информацию по вашей сети. При отсутсви некоторых Данных Вы сможете получить их вероятностное распредееление.') 
    duration=(st.sidebar.text_input('Продолжительность сосединения (секунды)',))
    protocol_type=st.sidebar.selectbox('протокол подключения', ['','tcp','udp','icmp'])
    service=st.sidebar.selectbox('Сетевая служба',['','http', 'private', 'domain_u', 'smtp', 'ftp_data', 'eco_i', 'telnet', 'other', 'ecr_i', 'ftp', 'finger', 'pop_3', 'auth', 'imap4',
                                            'Z39_50', 'bgp', 'iso_tsap', 'uucp', 'whois', 'uucp_path', 'time', 'courier', 'vmnet', 'nnsp', 'domain', 'urp_i', 'ctf',
                                            'csnet_ns', 'supdup', 'discard', 'gopher', 'daytime', 'sunrpc', 'http_443', 'systat', 'link', 'name', 'hostnames',
                                            'exec', 'efs', 'mtp', 'echo', 'login', 'klogin', 'ldap', 'netbios_dgm', 'netstat', 'netbios_ns', 'netbios_ssn',
                                            'ssh', 'nntp', 'kshell', 'sql_net', 'IRC', 'ntp_u', 'pop_2', 'remote_job', 'rje', 'shell', 'printer', 'X11'])
    flag =st.sidebar.selectbox('Статус соеденения', ['','SF', 'S0', 'REJ', 'RSTR', 'SH', 'RSTO', 'S1', 'RSTOS0', 'S3','S2', 'OTH'])
    src_bytes = st.sidebar.text_input('Количество байтов переданных от источника к месту назначения в одном соединении')
    dst_bytes=st.sidebar.text_input('Количество байтов данных, переданных из места назначения в источник в одном соединении',)
    wrong_fragment=st.sidebar.selectbox('wrong fragments',['',0,1,3])
    hot=st.sidebar.selectbox('Количество «горячих» индикаторов в содержимом, таких как: вход в системный каталог, создание программ и выполнение программ',['',0,1,2,3,'other'])
    logged_in=st.sidebar.selectbox('Статус входа в систему', ['','yes','otherwise',])
    num_compromised=st.sidebar.text_input('Количество скомпрометированных условий',)
    rerror_rate=st.sidebar.text_input('% подключений с ошибками REJ',)
    src_count=st.sidebar.text_input('Количество подключений к той же службе (номер порта), что и текущее подключение в сети за последние две секунды',)
    diff_srv_rate = st.sidebar.text_input('% подключений к различным сервисам')
    srv_diff_host_rate = st.sidebar.text_input('% подключений к разным хостам')
    dst_host_count=st.sidebar.text_input('Количество соединений, имеющих один и тот же IP-адрес узла назначения',)
    dst_host_same_src_port_rate=st.sidebar.text_input('% подключений к текущему хосту, имеющему тот же src-порт',)
    last_flag=st.sidebar.text_input('Последний флаг сети',)

    st.sidebar.markdown('  ')

    evidence = [duration, protocol_type, service, flag,src_bytes, dst_bytes, wrong_fragment,hot,logged_in,num_compromised,
                    rerror_rate,diff_srv_rate,srv_diff_host_rate,src_count,dst_host_count,dst_host_same_src_port_rate,last_flag]
    evidence_text =['duration', 'protocol_type', 'service', 'flag','src_bytes','dst_bytes', 'wrong_fragment', 'hot', 'logged_in', 'num_compromised',
                        'rerror_rate', 'srv_count','diff_srv_rate','srv_diff_host_rate', 'dst_host_count', 'dst_host_same_src_port_rate', 'last_flag']
            
            
    if 'button1' not in st.session_state:
        st.session_state.button1 = False
    if 'button2' not in st.session_state:
        st.session_state.button2 = False


    if st.button('Запусть'):
        st.session_state.button1 = True
        st.session_state.button2 = False

   
    if st.button('Просмотр дополнительной информации'):
        st.session_state.button1 = True
        st.session_state.button2 = True

    if st.session_state.button1:
        get_ev = {}
        for i, j in zip(evidence,evidence_text):
            if i != '':
                
               if j == 'protocol_type':
                    get_ev[j] = protocol[i] 
                    
               elif j == 'service':
                   get_ev[j] = ser[i]

               elif j == 'flag':
                   get_ev[j] = fl[i]

               elif j == 'logged_in':
                   if i == "yes":
                        get_ev[j] = 0
                   else:
                        get_ev[j] = 1
               elif j =='wrong_fragment':
                   if i == 0:
                       get_ev[j]=1
                   elif i==1:
                       get_ev[j]=2
                   else:
                       get_ev[j]=3
               elif j=='hot':
                   if i == 'other':
                       get_ev[j] = 5
                   else:
                       get_ev[j] = i+1
               else:
                   #get_ev[j] = int(i)
                   idx = (df[j] - int(i)).abs().idxmin()
                   y = j+'1'
                   get_ev[j]=df[y].iloc[idx]


        if classification_type == "Биномиальный":
            x=bn.inference.fit(model_bin, variables=['attack'], evidence=get_ev)
            keys = [key for key, val in attacks_01.items() if val == x.df.p.idxmax()]
            st.write("Результат: ",keys[0] ,"Вероятность: ", x.df.p.max())
            if st.session_state.button2:
                for i, value in enumerate(x.df.attack):
                     for key, val in attacks_01.items():
                        if value == val:
                            x.df.at[i, 'attack'] = key
                            break
                st.write("Полная таблица значений:", "\n" ,x.df )
        elif classification_type == 'Определение типа атаки':
            x=bn.inference.fit(model_mul01234, variables=['attack'], evidence=get_ev)
            keys = [key for key, val in attacks.items() if val == x.df.p.idxmax()]
            st.write("Результат: ",keys[0] ,"Вероятность: ", x.df.p.max())
            if st.session_state.button2:
                for i, value in enumerate(x.df.attack):
                     for key, val in attacks.items():
                        if value == val:
                            x.df.at[i, 'attack'] = key
                            break
                st.write("Полная таблица значений:", "\n" ,x.df )

        else:
            x=bn.inference.fit(model_mul012, variables=['attack'], evidence=get_ev)
            keys = [key for key, val in attacks_5.items() if val == x.df.p.idxmax()]
            st.write("Результат: ",keys[0] ,"Вероятность: ", x.df.p.max())
            if st.session_state.button2:
                for i, value in enumerate(x.df.attack):
                     for key, val in attacks_5.items():
                        if value == val:
                            x.df.at[i, 'attack'] = key
                            break
                st.write("Полная таблица значений:", "\n" ,x.df )
            

    if st.button('Просмотр информации по отсутствующим узлам '):

        st.image("plot.png")
        st.write('Информация по отсутствующим данным:',)
        for i, j in zip(evidence,evidence_text):
            if i =='':
                e=bn.inference.fit(model_bin, variables=[j], evidence=get_ev)
                if j == 'protocol_type':
                    e.df.protocol_type.iloc[0]='icmp'
                    e.df.protocol_type.iloc[1]='tcp'
                    e.df.protocol_type.iloc[2]='udp'
                elif j == 'flag':
                    for n in range(11):
                        keys = [k for k, v in fl.items() if v == n+1]
                        e.df.flag.iloc[n]=keys[0]
                elif j == 'service':
                    for n in range(61):
                        keys = [k for k, v in ser.items() if v == n+1]
                        e.df.service.iloc[n]=keys[0]
                        
                elif j == 'hot':
                    e.df=e.df.drop(0)
                elif j == 'logged_in':
                    e.df.logged_in.iloc[0] = 'yes'
                    e.df.logged_in.iloc[1] = 'other'
                else:
                    e.df=e.df.sort_values('p', ascending=False).head(5)
                st.write(e.df) 


elif app_mode == 'Main':
    st.title('Анализ и диагностирование сетевого трафика')
    st.subheader('Добро пожаловать, данный сервис предназначен для определения сетевых вторжений и аномалий.')
    st.subheader('Данный сервис основан на байесовских сетях и обучен на базе данных KDD Cup 99.', )
    if st.button('Информация о переменных'):
        info = pd.read_excel("info.xlsx")
        st.dataframe(info)

    
    