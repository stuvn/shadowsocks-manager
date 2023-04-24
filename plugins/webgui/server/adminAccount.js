const macAccount = appRequire('plugins/macAccount/index');
const account = appRequire('plugins/account/index');
const dns = require('dns');
const net = require('net');
const knex = appRequire('init/knex').knex;
const flowPlugin = appRequire('plugins/flowSaver/flow');
const moment = require('moment');

const formatMacAddress = mac => mac.replace(/-/g, '').replace(/:/g, '').toLowerCase();

exports.getMacAccount = (req, res) => {
  const userId = +req.query.userId;
  macAccount.getAccount(userId, -1).then(success => {
    res.send(success);
  }).catch(err => {
    console.log(err);
    res.status(403).end();
  });
};

exports.addMacAccount = (req, res) => {
  const mac = formatMacAddress(req.params.macAddress);
  const userId = req.body.userId;
  const accountId = req.body.accountId;
  const serverId = req.body.serverId;
  macAccount.newAccount(mac, userId, serverId, accountId).then(success => {
    res.send('success');
  }).catch(err => {
    console.log(err);
    res.status(403).end();
  });
};

exports.editMacAccount = (req, res) => {
  const id = req.body.id;
  const mac = formatMacAddress(req.body.macAddress);
  const userId = req.body.userId;
  const accountId = req.body.accountId;
  const serverId = req.body.serverId;
  macAccount.editAccount(id, mac, serverId, accountId).then(success => {
    res.send('success');
  }).catch(err => {
    console.log(err);
    res.status(403).end();
  });
};

exports.deleteMacAccount = (req, res) => {
  const accountId = +req.query.id;
  macAccount.deleteAccount(accountId).then(success => {
    res.send('success');
  }).catch(err => {
    console.log(err);
    res.status(403).end();
  });
};

exports.getMacAccountForUser = (req, res) => {
  const mac = req.params.macAddress;
  const ip = req.headers['x-real-ip'] || req.connection.remoteAddress;
  const noPassword = !!(+req.query.noPassword);
  const noFlow = !!(+req.query.noFlow);
  const type = req.query.type || 'Shadowsocks';
  macAccount.getAccountForUser(mac.toLowerCase(), ip, {
    type,
    noPassword,
    noFlow,
  }).then(success => {
    res.send(success);
  }).catch(err => {
    console.log(err);
    res.status(403).end();
  });
};

exports.getNoticeForUser = (req, res) => {
  const mac = req.params.macAddress;
  const ip = req.headers['x-real-ip'] || req.connection.remoteAddress;
  macAccount
  .getNoticeForUser(mac.toLowerCase(), ip)
  .then(success => {
    res.send(success);
  }).catch(err => {
    console.log(err);
    res.status(403).end();
  });
};

exports.banAccount = (req, res) => {
  const serverId = +req.params.serverId;
  const accountId = +req.params.accountId;
  const time = +req.body.time;
  account.banAccount({
    serverId,
    accountId,
    time,
  }).then(success => {
    res.send('success');
  }).catch(err => {
    console.log(err);
    res.status(403).end();
  });
};

exports.getBanAccount = (req, res) => {
  const serverId = +req.params.serverId;
  const accountId = +req.params.accountId;
  account.getBanAccount({
    serverId,
    accountId,
  }).then(success => {
    res.send(success);
  }).catch(err => {
    console.log(err);
    res.status(403).end();
  });
};

const isMacAddress = str => {
  return str.match(/^([A-Fa-f0-9]{2}[:-]?){5}[A-Fa-f0-9]{2}$/);
};

const getAddress = (address, ip) => {
  let myAddress = address;
  if(address.indexOf(':') >= 0) {
    const hosts = address.split(':');
    const number = Math.ceil(Math.random() * (hosts.length - 1));
    myAddress = hosts[number];
  }
  if(!ip) {
    return Promise.resolve(myAddress);
  }
  if(net.isIP(myAddress)) {
    return Promise.resolve(myAddress);
  }
  return new Promise((resolve, reject) => {
    dns.lookup(myAddress, (err, myAddress, family) => {
      if(err) {
        return reject(err);
      }
      return resolve(myAddress);
    });
  });
};

const urlsafeBase64 = str => {
  return Buffer.from(str).toString('base64').replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
};

exports.getSubscribeAccountForUser = async (req, res) => {
  try {
    const ssr = req.query.ssr;
    let type = req.query.type || 'shadowrocket';
    if(ssr === '1') { type = 'ssr'; }
    const resolveIp = req.query.ip;
    const showFlow = req.query.flow || 0;
    const token = req.params.token;
    const ip = req.headers['x-real-ip'] || req.connection.remoteAddress;
    let subscribeAccount;
    if(isMacAddress(token)) {
      subscribeAccount = await macAccount.getMacAccountForSubscribe(token, ip);
    } else {
      const isSubscribeOn = await knex('webguiSetting').where({
        key: 'account'
      }).then(s => s[0]).then(s => JSON.parse(s.value).subscribe);
      if(!isSubscribeOn) { return res.status(404).end(); }
      subscribeAccount = await account.getAccountForSubscribe(token, ip);
    }
    for(const s of subscribeAccount.server) {
      s.host = await getAddress(s.host, +resolveIp);
    }
    const baseSetting = await knex('webguiSetting').where({
      key: 'base'
    }).then(s => s[0]).then(s => JSON.parse(s.value));
    const ssdInfo = {
      airport: 'ssmgr',
      port: subscribeAccount.account.port,
      encryption: 'aes-256-gcm',
      password: subscribeAccount.account.password,
      servers: subscribeAccount.server.filter(s => !s.subscribeName).map(s => {
        return {
          id: s.id,
          server: s.host,
          port: subscribeAccount.account.port + s.shift,
          encryption: s.method,
          remarks: s.name,
        };
      }),
    };
    if(subscribeAccount.account.type !== 1 && +showFlow) {
      const random = Math.floor(Math.random() * 9999) % (subscribeAccount.server.length - 1);
      const insert = JSON.parse(JSON.stringify(subscribeAccount.server[random]));
      const time = {
        '2': 7 * 24 * 3600000,
        '3': 30 * 24 * 3600000,
        '4': 24 * 3600000,
        '5': 3600000,
      };
      const expire = subscribeAccount.account.data.create + subscribeAccount.account.data.limit * time[subscribeAccount.account.type];
      ssdInfo.expiry = moment(expire).format('YYYY-MM-DD HH:mm:ss');
      if(Date.now() >= expire) {
        insert.subscribeName = '已过期';
      } else if((expire - Date.now()) >= 48 * 3600 * 1000) {
        insert.subscribeName = moment(expire).format('YYYY-MM-DD过期');
      } else if((expire - Date.now()) >= 3600 * 1000) {
        insert.subscribeName = (Math.floor((expire - Date.now())/(3600 * 1000))) + '小时后过期';
      } else if((expire - Date.now()) > 0) {
        insert.subscribeName = (Math.floor((expire - Date.now())/(60 * 1000))) + '分钟后过期';
      }
      let insertFlow;
      if(subscribeAccount.account.multiServerFlow) {
        insertFlow = JSON.parse(JSON.stringify(subscribeAccount.server[random]));
        const flow = subscribeAccount.account.data.flow;
        const time = {
          '2': 7 * 24 * 3600000,
          '3': 30 * 24 * 3600000,
          '4': 24 * 3600000,
          '5': 3600000,
        };
        let from = subscribeAccount.account.data.create;
        let to = subscribeAccount.account.data.create + time[subscribeAccount.account.type];
        while(to <= Date.now()) {
          from = to;
          to = from + time[subscribeAccount.account.type];
        }
        const [ currentFlow ] = await flowPlugin.getServerPortFlowWithScale(insertFlow.id, subscribeAccount.account.id, [from, to], true);
        ssdInfo.traffic_used = currentFlow / (1000 * 1000 * 1000);
        ssdInfo.traffic_total = flow / (1000 * 1000 * 1000);
        const toFlowString = input => {
          const K = 1000;
          const M = 1000 * 1000;
          const G = 1000 * 1000 * 1000;
          const T = 1000 * 1000 * 1000 * 1000;
          const P = 1000 * 1000 * 1000 * 1000 * 1000;
          if (input < K) {
            return input + 'B';
          } else if (input < M) {
            return (input / K).toFixed(1) + 'KB';
          } else if (input < G) {
            return (input / M).toFixed(1) + 'MB';
          } else if (input < T) {
            return (input / G).toFixed(2) + 'GB';
          } else if (input < P) {
            return (input / T).toFixed(3) + 'TB';
          } else {
            return input;
          }
        };
        insertFlow.subscribeName = toFlowString(currentFlow) + '/' + toFlowString(flow);
      }
      subscribeAccount.server.unshift(insert);
      if(insertFlow) { subscribeAccount.server.unshift(insertFlow); }
    }
    if(type === 'ssd') {
      return res.send('ssd://' + Buffer.from(JSON.stringify(ssdInfo)).toString('base64'));
    }
	
    if(type === 'surfboard') {
      const template = [
        '[General]',
        'skip-proxy = 127.0.0.1, 192.168.0.0/16, 10.0.0.0/8, 172.16.0.0/12, 100.64.0.0/10, localhost, *.local',
        'dns-server = 114.114.114.114, 223.5.5.5, system',
        'always-real-ip = stun.l.google.com',	  
        '[Proxy]',
        '@{SERVERS}',
        '[Proxy Group]',
        '@{GROUP}',
        '[Rule]',		
		'# BAT',
		'DOMAIN-SUFFIX,baidu.com,DIRECT',
		'DOMAIN-SUFFIX,baidupcs.com,DIRECT',
		'DOMAIN-SUFFIX,bdimg.com,DIRECT',
		'DOMAIN-SUFFIX,bdstatic.com,DIRECT',
		'DOMAIN-SUFFIX,alipay.com,DIRECT',
		'DOMAIN-SUFFIX,alipayobjects.com,DIRECT',
		'DOMAIN-SUFFIX,alicdn.com,DIRECT',
		'DOMAIN-SUFFIX,aliyun.com,DIRECT',
		'DOMAIN-SUFFIX,aliyuncs.com,DIRECT',
		'DOMAIN-SUFFIX,taobao.com,DIRECT',
		'DOMAIN-SUFFIX,tmall.com,DIRECT',
		'DOMAIN-SUFFIX,qq.com,DIRECT',
		'DOMAIN-SUFFIX,qqurl.com,DIRECT',
		'# China',
		'DOMAIN-SUFFIX,cn,DIRECT',
		'DOMAIN-SUFFIX,126.net,DIRECT',
		'DOMAIN-SUFFIX,163.com,DIRECT',
		'DOMAIN-SUFFIX,163.net,DIRECT',
		'DOMAIN-SUFFIX,amap.com,DIRECT',
		'DOMAIN-SUFFIX,autonavi.com,DIRECT',
		'DOMAIN-SUFFIX,ccgslb.com,DIRECT',
		'DOMAIN-SUFFIX,ccgslb.net,DIRECT',
		'DOMAIN-SUFFIX,cnbeta.com,DIRECT',
		'DOMAIN-SUFFIX,cnbetacdn.com,DIRECT',
		'DOMAIN-SUFFIX,douban.com,DIRECT',
		'DOMAIN-SUFFIX,doubanio.com,DIRECT',
		'DOMAIN-SUFFIX,gtimg.com,DIRECT',
		'DOMAIN-SUFFIX,hao123.com,DIRECT',
		'DOMAIN-SUFFIX,haosou.com,DIRECT',
		'DOMAIN-SUFFIX,ifeng.com,DIRECT',
		'DOMAIN-SUFFIX,iqiyi.com,DIRECT',
		'DOMAIN-SUFFIX,jd.com,DIRECT',
		'DOMAIN-SUFFIX,mi.com,DIRECT',
		'DOMAIN-SUFFIX,miui.com,DIRECT',
		'DOMAIN-SUFFIX,netease.com,DIRECT',
		'OMAIN-SUFFIX,netease.im,DIRECT',
		'DOMAIN-SUFFIX,qdaily.com,DIRECT',
		'DOMAIN-SUFFIX,qhimg.com,DIRECT',
		'DOMAIN-SUFFIX,qihucdn.com,DIRECT',
		'DOMAIN-SUFFIX,qiniucdn.com,DIRECT',
		'DOMAIN-SUFFIX,qiniudn.com,DIRECT',
		'DOMAIN-SUFFIX,sogou.com,DIRECT',
		'DOMAIN-SUFFIX,sogoucdn.com,DIRECT',
		'DOMAIN-SUFFIX,sohu.com,DIRECT',
		'DOMAIN-SUFFIX,steamstatic.com,DIRECT',
		'DOMAIN-SUFFIX,suning.com,DIRECT',
		'DOMAIN-SUFFIX,tudou.com,DIRECT',
		'DOMAIN-SUFFIX,upaiyun.com,DIRECT',
		'DOMAIN-SUFFIX,clouddn.com,DIRECT',
		'DOMAIN-SUFFIX,upyun.com,DIRECT',
		'DOMAIN-SUFFIX,weibo.com,DIRECT',
		'DOMAIN-SUFFIX,youku.com,DIRECT',
		'DOMAIN-SUFFIX,xunlei.com,DIRECT',
		'DOMAIN-SUFFIX,zhihu.com,DIRECT',
		'DOMAIN-SUFFIX,zhimg.com,DIRECT',
		'# Telegram',
		'IP-CIDR,91.108.56.0/22,SelectGroup,no-resolve',
		'IP-CIDR,91.108.4.0/22,SelectGroup,no-resolve',
		'IP-CIDR,91.108.8.0/22,SelectGroup,no-resolve',
		'IP-CIDR,109.239.140.0/24,SelectGroup,no-resolve',
		'IP-CIDR,149.154.160.0/20,SelectGroup,no-resolve',
		'IP-CIDR,149.154.164.0/22,SelectGroup,no-resolve',
		'# LAN',
        'DOMAIN-SUFFIX,local,DIRECT',
        'IP-CIDR,192.168.0.0/16,DIRECT',
        'IP-CIDR,10.0.0.0/8,DIRECT',
        'IP-CIDR,172.16.0.0/12,DIRECT',
        'IP-CIDR,127.0.0.0/8,DIRECT',
        'IP-CIDR,100.64.0.0/10,DIRECT',
		'# Final',
        'GEOIP,CN,DIRECT',
        'FINAL,SelectGroup' 
      ].join('\n')
      .replace('@{SERVERS}', subscribeAccount.server.map(s => {
		if(s.comment == 'http' || s.comment == 'tls') { 
            return `'${s.name}' = ss, ${s.host}, ${(subscribeAccount.account.port + s.shift)}, encrypt-method=${s.method}, password=${subscribeAccount.account.password}, udp-relay=true, obfs=${s.comment}, obfs-host=www.apple.com\n`;
		} else {
			return `'${s.name}' = ss, ${s.host}, ${(subscribeAccount.account.port + s.shift)}, encrypt-method=${s.method}, password=${subscribeAccount.account.password}, udp-relay=true\n`;
		}
      }).join(''))
      .replace('@{GROUP}', 'SelectGroup = select,' + subscribeAccount.server.map(s => {
        return `'${s.subscribeName || s.name}'`;
      }).join(','));
      return res.send(template);
    }
	
    const ss_clash = server => {
    if(server.comment == 'http' || server.comment == 'tls') {
      return {
        cipher: server.method,
        name: server.name,
        password: String(subscribeAccount.account.password),
        port: subscribeAccount.account.port + server.shift,
        server: server.host,
        type: 'ss',
        plugin: 'obfs',
	'plugin-opts': { 
		mode: server.comment,
		host: 'www.apple.com'
	} 
      };
    } else {
      return {
        cipher: server.method,
        name: server.name,
        password: String(subscribeAccount.account.password),
        port: subscribeAccount.account.port + server.shift,
        server: server.host,
        type: 'ss'
      };
    }
    }

    if(type === 'clash') {
      const yaml = require('js-yaml');
      const clashConfig = appRequire('plugins/webgui/server/clash');
      let cs = { Proxy: [], proxies: [] };
      subscribeAccount.server.map(server => {
        cs.Proxy.push(ss_clash(server));
        cs.proxies.push(server.name);
      });

      clashConfig.proxies = cs.Proxy;

      clashConfig['proxy-groups'][0] = {
        name: '🎯 节点选择',
        type: 'select',
        proxies: cs.proxies,
        proxies: ['🚀 自动选优'].concat(cs.proxies),
      };
      clashConfig['proxy-groups'][1] = {
        name: '🚀 自动选优',
        type: 'url-test',
        url: 'http://www.gstatic.com/generate_204',
        interval: 300,
        proxies: cs.proxies,
      };
      clashConfig['proxy-groups'][2] = {
        name: '⛔ 应用拦截',
        type: 'select',
        proxies: ['REJECT'],
      };
      
      return res.send(yaml.safeDump(clashConfig));
    }

    const result = subscribeAccount.server.map(s => {
      if(type === 'shadowrocket') {	
        if(s.comment == 'http' || s.comment == 'tls') {
          var str = Buffer.from(s.method + ':' + subscribeAccount.account.password + '@' + s.host + ':' + (subscribeAccount.account.port + s.shift)).toString('base64'); str = str.replace(/\//g , '_'); return 'ss://' + str + '/?plugin=obfs-local%3bobfs%3d' + s.comment + '%3bobfs-host%3dwww.apple.com' + '#' + (s.subscribeName || s.name);
	      } else {
	        var str = Buffer.from(s.method + ':' + subscribeAccount.account.password + '@' + s.host + ':' + (subscribeAccount.account.port + s.shift)).toString('base64'); str = str.replace(/\//g , '_'); return 'ss://' + str + '#' + (s.subscribeName || s.name);
	      }
      } else if(type === 'ssr') {		  
		return   'ProxySS = ss, ' + s.host + ', ' + (subscribeAccount.account.port + s.shift) + ', encrypt-method=' + s.method + ', password=' + subscribeAccount.account.password + ', udp-relay=true, obfs=' + s.comment + ', obfs-host=www.apple.com, obfs-uri=/'
        // return 'ssr://' + urlsafeBase64(s.host + ':' + (subscribeAccount.account.port + s.shift) + ':origin:' + s.method + ':plain:' + urlsafeBase64(subscribeAccount.account.password) +  '/?obfsparam=&remarks=' + urlsafeBase64(s.subscribeName || s.name) + '&group=' + urlsafeBase64(baseSetting.title));
      }
    }).join('\r\n');
    return res.send(Buffer.from(result).toString('base64'));
  } catch (err) {
    console.log(err);
    res.status(403).end();
  }
};
