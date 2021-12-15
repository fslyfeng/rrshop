<?php
if (!(defined('IN_IA'))) 
{
	exit('Access Denied');
}
include('wxpaydemo.php');
require_once('AopClient.php');
require_once('AlipayTradeAppPayRequest.php');
require_once('AopEncrypt.php');
class Index_EweiShopV2Page extends MobilePage 
{
	protected function getWapSet() 
	{
		global $_W;
		global $_GPC;
		$set = m('common')->getSysset(array('shop', 'wap'));
		$set['wap']['color'] = ((empty($set['wap']['color']) ? '#fff' : $set['wap']['color']));
		$params = array();
		if (!(empty($_GPC['mid']))) 
		{
			$params['mid'] = $_GPC['mid'];
		}
		if (!(empty($_GPC['backurl']))) 
		{
			$params['backurl'] = $_GPC['backurl'];
		}
		$set['wap']['loginurl'] = mobileUrl('account/login', $params);
		$set['wap']['regurl'] = mobileUrl('account/register', $params);
		$set['wap']['forgeturl'] = mobileUrl('account/forget', $params);
		return $set;
	}
	public function login() 
	{
		global $_W;
		global $_GPC;
		if (is_weixin() || !(empty($_GPC['__ewei_shopv2_member_session_' . $_W['uniacid']]))) 
		{
			header('location: ' . mobileUrl());
		}
		if ($_W['ispost']) 
		{
			$sns = $_GPC['sns'];
			if($sns =="web"||empty($_GPC['sns']))
			{
				$mobile = trim($_GPC['mobile']);
				$pwd = trim($_GPC['pwd']);
				$member = pdo_fetch('select id,openid,mobile,pwd,salt from ' . tablename('ewei_shop_member') . ' where mobile=:mobile and mobileverify=1 and uniacid=:uniacid limit 1', array(':mobile' => $mobile, ':uniacid' => $_W['uniacid']));
				if (empty($member)) 
				{
					show_json(0, '用户不存在');
				}
				if (md5($pwd . $member['salt']) !== $member['pwd']) 
				{
					show_json(0, '用户或密码错误');
				}
				m('account')->setLogin($member);
				show_json(1, '登录成功');
			}else if($sns =="wx")
			{
				$tmp = m('member')->checkMemberSNS($sns);
				$code = trim($_GPC['code']);
				if ($_GET['openid']) 
				{
					if ($sns == 'qq') 
					{
						$_GET['openid'] = 'sns_qq_' . $_GET['openid'];
					}
					if ($sns == 'wx') 
					{
						$_GET['openid'] = 'sns_wx_' . $_GET['openid'];
					}
					m('account')->setLogin($_GET['openid']);
					show_json(1, '登录成功');
				}else
				{
					show_json(0, '微信登录失败，获取openid失败');
				}
			}
			
		}
		$set = $this->getWapSet();
		$backurl = '';
		if (!(empty($_GPC['backurl']))) 
		{
			$backurl = $_W['siteroot'] . 'app/index.php?' . base64_decode(urldecode($_GPC['backurl']));
		}
		$wapset = $_W['shopset']['wap'];
		$sns = $wapset['sns'];
		include $this->template('login', NULL, true);
	}
	public function register() 
	{
		$this->rf(0);
	}
	public function forget() 
	{
		$this->rf(1);
	}
	protected function rf($type) 
	{
		global $_W;
		global $_GPC;
		if (is_weixin() || !(empty($_GPC['__ewei_shopv2_member_session_' . $_W['uniacid']]))) 
		{
			header('location: ' . mobileUrl());
		}
		if ($_W['ispost']) 
		{
			$mobile = trim($_GPC['mobile']);
			$verifycode = trim($_GPC['verifycode']);
			$pwd = trim($_GPC['pwd']);
			if (empty($mobile)) 
			{
				show_json(0, '请输入正确的手机号');
			}
			if (empty($verifycode)) 
			{
				show_json(0, '请输入验证码');
			}
			if (empty($pwd)) 
			{
				show_json(0, '请输入密码');
			}
			$key = '__ewei_shopv2_member_verifycodesession_' . $_W['uniacid'] . '_' . $mobile;
			if (!(isset($_SESSION[$key])) || ($_SESSION[$key] !== $verifycode) || !(isset($_SESSION['verifycodesendtime'])) || (($_SESSION['verifycodesendtime'] + 600) < time())) 
			{
				show_json(0, '验证码错误或已过期!');
			}
			$member = pdo_fetch('select id,openid,mobile,pwd,salt from ' . tablename('ewei_shop_member') . ' where mobile=:mobile and mobileverify=1 and uniacid=:uniacid limit 1', array(':mobile' => $mobile, ':uniacid' => $_W['uniacid']));
			if (empty($type)) 
			{
				if (!(empty($member))) 
				{
					show_json(0, '此手机号已注册, 请直接登录');
				}
				$salt = ((empty($member) ? '' : $member['salt']));
				if (empty($salt)) 
				{
					$salt = m('account')->getSalt();
				}
				$openid = ((empty($member) ? '' : $member['openid']));
				$nickname = ((empty($member) ? '' : $member['nickname']));
				if (empty($openid)) 
				{
					$openid = 'wap_user_' . $_W['uniacid'] . '_' . $mobile;
					$nickname = substr($mobile, 0, 3) . 'xxxx' . substr($mobile, 7, 4);
				}
				$data = array('uniacid' => $_W['uniacid'], 'mobile' => $mobile, 'nickname' => $nickname, 'openid' => $openid, 'pwd' => md5($pwd . $salt), 'salt' => $salt, 'createtime' => time(), 'mobileverify' => 1, 'comefrom' => 'mobile');
			}
			else 
			{
				if (empty($member)) 
				{
					show_json(0, '此手机号未注册');
				}
				$salt = m('account')->getSalt();
				$data = array('salt' => $salt, 'pwd' => md5($pwd . $salt));
			}
			if (empty($member)) 
			{
				pdo_insert('ewei_shop_member', $data);
				if (method_exists(m('member'), 'memberRadisCountDelete')) 
				{
					m('member')->memberRadisCountDelete();
				}
			}
			else 
			{
				pdo_update('ewei_shop_member', $data, array('id' => $member['id']));
			}
			if (p('commission')) 
			{
				p('commission')->checkAgent($openid);
			}
			unset($_SESSION[$key]);
			show_json(1, (empty($type) ? '注册成功' : '密码重置成功'));
		}
		$sendtime = $_SESSION['verifycodesendtime'];
		if (empty($sendtime) || (($sendtime + 60) < time())) 
		{
			$endtime = 0;
		}
		else 
		{
			$endtime = 60 - time() - $sendtime;
		}
		$set = $this->getWapSet();
		include $this->template('rf', NULL, true);
	}
	public function logout() 
	{
		global $_W;
		global $_GPC;
		$key = '__ewei_shopv2_member_session_' . $_W['uniacid'];
		isetcookie($key, false, -100);
		header('location: ' . mobileUrl());
		exit();
	}
	public function sns() 
	{
     
		global $_W;
		global $_GPC;
		if (is_weixin() || !(empty($_GPC['__ewei_shopv2_member_session_' . $_W['uniacid']]))) 
		{
			header('location: ' . mobileUrl());
		}
		$sns = trim($_GPC['sns']);
          

		if (!($_W['ispost']) && !(empty($sns)) && (empty($_GPC['openid']))) 
		{

			$tmp = m('member')->checkMemberSNS($sns);
           
		}
      	

		if ($_GET['openid']) 
		{
			if ($sns == 'qq') 
			{
				$_GET['openid'] = 'sns_qq_' . $_GET['openid'];
			}
			if ($sns == 'wx') 
			{
				$_GET['openid'] = 'sns_wx_' . $_GET['openid'];
			}
			m('account')->setLogin($_GET['openid']);
          	 
		}
       	
		$backurl = '';
		if (!(empty($_GPC['backurl']))) 
		{
			$backurl = $_W['siteroot'] . 'app/index.php?' . base64_decode(urldecode($_GPC['backurl']));
		}
		$backurl = ((empty($backurl) ? mobileUrl(NULL, NULL, true) : trim($backurl)));
		header('location: ' . $backurl);
	}
         public function get_pay_config()
	{
          
	        global $_W;
	        $sec = m("common")->getSec();
                    $sec = iunserializer($sec["sec"]);	
                    $sec['app_alipay']["ali_notify_url"] = $_W["siteroot"] . "addons/ewei_shopv2/payment/alipay/notify.php";		
                   echo json_encode($sec) ;   
		
		
	}



	public function orderstatus()
	{
      	
		global $_W;
        global $_GPC;
      	$paytype = $_GPC["paytype"];
      	$paytype = $paytype=="alipay"?22:21;
      	if(strpos($_GPC["ordersn"],'RC') !==false){
           $log = pdo_fetch("SELECT * FROM " . tablename("ewei_shop_member_log") . " WHERE `logno`=:logno limit 1", array( ":logno" => $_GPC["ordersn"] ));
          if($log['status']==0)
          {
            pdo_update("ewei_shop_member_log", array( "status" =>1 ), array( "logno" =>$_GPC["ordersn"] ));
            $row = pdo_fetch("SELECT * FROM " . tablename("ewei_shop_member") . " WHERE `openid`=:openid limit 1", array( ":openid" => $log['openid'] ));
            if($row['uid']==0)
            {
              pdo_update("ewei_shop_member", array( "credit2" =>$row['credit2']+$log["money"] ), array( "openid" => $log['openid'] ));
            }else
            {
                  $row2 = pdo_fetch("SELECT * FROM " . tablename("mc_members") . " WHERE `uid`=:uid limit 1", array( ":uid" => $row['uid'] ));
                  pdo_update("mc_members", array( "credit2" =>$row2['credit2']+$log["money"] ), array( "uid" => $row['uid'] ));
            }
          }
        }else
        {
          //$orderid = intval($_GPC["globe_orderid_"]);
          //$app_paytype= intval($_GPC["app_paytype"]);
          $ordersn = $_GPC["ordersn"];
          $tradeno = $_GPC["tradeno"];
          $result=pdo_update("ewei_shop_order", array( "status" =>1,"paytime"=>time(),"paytype" =>$paytype ), array( "ordersn" => $ordersn, "uniacid" => $_W["uniacid"] ));
          echo json_encode($result) ; 
        }
		  
      	
	}

   public function Pay_data()
   {
        if( isset($_POST['submit_wx'] )&& $_POST['submit_wx']=="true")
         {

         	    $fee=$_POST['fee'];
                 $app_wechat_appid=$_POST['wx_appid'];
                 $app_wechat_merchid=$_POST['wx_merchid'];
                 $app_wechat_apikey=$_POST['wx_apikey'];
                $pay_attach=$_POST['pay_attach'];
          
          		$ordersn =$_POST['ordersn'];
         	    $result_wx_pay=new wxpay($app_wechat_appid,$app_wechat_merchid,$app_wechat_apikey,$fee*100,$pay_attach,$ordersn);  
                 $result_wx_pay_data=$result_wx_pay->result_paydata;  
                 echo  ($result_wx_pay_data)    ;
         }
       
         if( isset($_POST['submit_ali'] )&& $_POST['submit_ali']=="true")
         {


                 global $_W;
         	    $fee=$_POST['fee'];
         	    $rand = rand(10000, 99999);
                $order=$_POST['ordersn'];
                $set_ali_appid=    $_POST['ali_appid'];
                $set_ali_PrivateKey=   $_POST['ali_private_key_rsa2'];    
                $set_ali_PublicKey= $_POST['ali_public_key_rsa2'];       

                $ali_notify_url= $_POST['ali_notify_url'];
                $pay_attach=$_POST['pay_attach'];

         	    $result_ali_pay_data =$this->Alipay($fee,$order,$pay_attach,$set_ali_appid,$set_ali_PrivateKey,$set_ali_PublicKey,$ali_notify_url);//==================================用户自定义参数
                 echo $result_ali_pay_data   ;
         }
   }
    
    public function Alipay($price,$id,$name,$appId,$PrivateKey,$PublicKey,$ali_notify_url){
      	
      	$type = 0;
      	if(strpos($_POST['ordersn'],'RC') !==false){
           $type = 1;
        }
      	$params = array('out_trade_no' => $_POST['ordersn'], 'total_amount' => $price, 'subject' =>$name . '订单', 'body' => $_W['uniacid'] . ':'.$type.':NATIVEAPP');
			$sec = m('common')->getSec();
			$sec = iunserializer($sec['sec']);
			$alipay_config = $sec['app_alipay'];
		//print_r($alipay_config);
      	
		$res = $this->alipay_build($params, $alipay_config);
      	print_r($res);
      exit;
	    $aop = new AopClient;
	    $aop->gatewayUrl = "https://openapi.alipay.com/gateway.do";
	   
	    $aop->appId = $appId;
	    
	    $aop->rsaPrivateKey = $PrivateKey;
	  
	    $aop->alipayrsaPublicKey = $PublicKey;
	    $aop->format = "json";
	    $aop->charset = "UTF-8";
	    $aop->signType = "RSA2";
	    $request = new AlipayTradeAppPayRequest();
	    $bizcontent = "{\"body\":\"test\","
	        . "\"subject\": \"$name\","
	        . "\"out_trade_no\": \"$id\","
	        . "\"timeout_express\": \"30m\","
	        . "\"total_amount\": \"$price\","
	        . "\"product_code\":\"QUICK_MSECURITY_PAY\""
	        . "}";
		
      
	    $request->setNotifyUrl($ali_notify_url);
	    $request->setBizContent($bizcontent);
	    $response = $aop->sdkExecute($request);
	    return $response;
	    
	}   
  public function alipay_build($params, $config = array()) 
		{
			global $_W;
			$arr = array('app_id' => $config['appid'], 'method' => 'alipay.trade.app.pay', 'format' => 'JSON', 'charset' => 'utf-8', 'sign_type' => 'RSA2', 'timestamp' => date('Y-m-d H:i:s', time()), 'version' => '1.0', 'notify_url' => $_W['siteroot'] . 'addons/ewei_shopv2/payment/alipay/notify.php', 'biz_content' => json_encode(array('timeout_express' => '90m', 'product_code' => 'QUICK_MSECURITY_PAY', 'total_amount' => $params['total_amount'], 'subject' => $params['subject'], 'body' => $params['body'], 'out_trade_no' => $params['out_trade_no'])));
			ksort($arr);
			$string1 = '';
			foreach ($arr as $key => $v ) 
			{
				if (empty($v)) 
				{
					continue;
				}
				$string1 .= $key . '=' . $v . '&';
			}
			$string1 = rtrim($string1, '&');
    		//print_r($config);
    		$prevateKeytmp = $this->chackKey($config['private_key_rsa2'], false);
    		//print_r($prevateKeytmp);
			$pkeyid = openssl_pkey_get_private($prevateKeytmp);
			if ($pkeyid === false) 
			{
				return error(-1, '提供的私钥格式不对');
			}
    		//print_r("1");
			$signature = '';
			openssl_sign($string1, $signature, $pkeyid, OPENSSL_ALGO_SHA256);
			openssl_free_key($pkeyid);
    		//print_r("2");
			$signature = base64_encode($signature);
    		//print_r($signature);
			$arr['sign'] = $signature;
			return http_build_query($arr);
		}
  	public function chackKey($key, $public = true) 
	{
		if( empty($key) ) 
		{
			return $key;
		}
		if( $public ) 
		{
			if( strexists($key, "-----BEGIN PUBLIC KEY-----") ) 
			{
				$key = str_replace(array( "-----BEGIN PUBLIC KEY-----", "-----END PUBLIC KEY-----" ), "", $key);
			}
			$head_end = "-----BEGIN PUBLIC KEY-----\n{key}\n-----END PUBLIC KEY-----";
		}
		else 
		{
			if( strexists($key, "-----BEGIN RSA PRIVATE KEY-----") ) 
			{
				$key = str_replace(array( "-----BEGIN RSA PRIVATE KEY-----", "-----END RSA PRIVATE KEY-----" ), "", $key);
			}
			$head_end = "-----BEGIN RSA PRIVATE KEY-----\n{key}\n-----END RSA PRIVATE KEY-----";
		}
		$key = str_replace(array( "\r\n", "\r", "\n" ), "", trim($key));
		$key = wordwrap($key, 64, "\n", true);
		return str_replace("{key}", $key, $head_end);
	}
	public function verifycode() 
	{
		global $_W;
		global $_GPC;
		@session_start();
		$set = $this->getWapSet();
		$mobile = trim($_GPC['mobile']);
		$temp = trim($_GPC['temp']);
		$imgcode = trim($_GPC['imgcode']);
		if (empty($mobile)) 
		{
			show_json(0, '请输入手机号');
		}
		if (empty($temp)) 
		{
			show_json(0, '参数错误');
		}
		if (!(empty($_SESSION['verifycodesendtime'])) && (time() < ($_SESSION['verifycodesendtime'] + 60))) 
		{
			show_json(0, '请求频繁请稍后重试');
		}
		if (!(empty($set['wap']['smsimgcode']))) 
		{
			if (empty($imgcode)) 
			{
				show_json(0, '请输入图形验证码');
			}
			$imgcodehash = md5(strtolower($imgcode) . $_W['config']['setting']['authkey']);
			if ($imgcodehash != trim($_GPC['__code'])) 
			{
				show_json(-1, '请输入正确的图形验证码');
			}
		}
		$member = pdo_fetch('select id,openid,mobile,pwd,salt from ' . tablename('ewei_shop_member') . ' where mobile=:mobile and mobileverify=1 and uniacid=:uniacid limit 1', array(':mobile' => $mobile, ':uniacid' => $_W['uniacid']));
		if (($temp == 'sms_forget') && empty($member)) 
		{
			show_json(0, '此手机号未注册');
		}
		if (($temp == 'sms_reg') && !(empty($member))) 
		{
			show_json(0, '此手机号已注册，请直接登录');
		}
		$sms_id = $set['wap'][$temp];
		if (empty($sms_id)) 
		{
			show_json(0, '短信发送失败(NOSMSID)');
		}
		$key = '__ewei_shopv2_member_verifycodesession_' . $_W['uniacid'] . '_' . $mobile;
		@session_start();
		$code = random(5, true);
		$shopname = $_W['shopset']['shop']['name'];
		$ret = array('status' => 0, 'message' => '发送失败');
		if (com('sms')) 
		{
			$ret = com('sms')->send($mobile, $sms_id, array('验证码' => $code, '商城名称' => (!(empty($shopname)) ? $shopname : '商城名称')));
		}
		if ($ret['status']) 
		{
			$_SESSION[$key] = $code;
			$_SESSION['verifycodesendtime'] = time();
			show_json(1, '短信发送成功');
		}
		show_json(0, $ret['message']);
	}
}
?>