# scan-platform

![](./images/framework.png)

## Installation

1. Use `web/schema.sql` to initialize database
2. Set database account under `scanner/config.ini`
3. Download the latest release of [Apache ActiveMQ](http://activemq.apache.org/download.html), and rename as `manager`
4. Run the following commands to install requirements:

```
sudo apt install -y nmap openjdk-8-jre
sudo pip install -r web/requirements.txt
sudo pip install -r scanner/requirements.txt
```

## Usage

As for `Web` module:

```
./manager/bin/activemq/start
python web/app.py
```

As for `Scanner` module, which can be run distributedly:

```
python scanner/scan.py
```

## Result

Dashboard:

![](./images/01.png)

Detecting results:

![](./images/02.png)
