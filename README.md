---
typora-root-url: README.assets
---

# iot-authentication

Project for my paper "An Authentication Scheme for Large Scale Consumer Oriented Smart IoT Applications".

It contains my hlpsl code formal security analysis and python code for measuring performance.







![systemArchitecture](C:\Users\star\Desktop\iot-authenticaiton-paper\repository\iot-authentication\README.assets\systemArchitecture.png)

​	The system consists of four entities: IoT device, back-end authentication server, back-end relay server, and a mobile application.

​	The IoT device is a typical smart device, which is widely available in the market, e.g., smart camera, Google Home, etc. The authentication server and the relay server are two components in the back-end, which are by the smart IoT application service provider. The authentication server is responsible for authenticating the device and the user. The relay server is responsible for forwarding remote communications between the device and the user. Separating the two servers are useful for scaling the authentication system. Because most of the remote communication is on relaying user’s access and control commands, the service provider can scale up the system by using more command relay servers. The mobile application runs on the user’s mobile phone. Through it, the user is able to communicate with the IoT device either locally or remotely.



## avispa

The code in "avispa" is my hlpsl code for my paper.

You need to download the tool: span to run my code

See http://people.irisa.fr/Thomas.Genet/span/



## python_code



### What needs to be done?

#### Create a database "as".

Execute as.sql to create the tables and datas.

The database is in AS.

#### Install python package

We use Python3.7 to run these code.

1. twisted
2. Crypto
3. pymysql
4. configparser

### How to run my code?

In "Run", there are four script: test_app, test_as, test_device, test_rs.

You can run them in you machine, since I fill their ip: localhost.

You can also run them in LAN, then you need to modify the ip in the code.

There are four roles in my code. 

Just run them directly, obey the instructions.

For example:

```
python3 test_as.py
```



### where are the performances?

The results are shown in the log.