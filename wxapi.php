<?php
//定义TOKEN秘钥，用于微信服务器和自定义服务器之间的校验
define("TOKEN", "wechat");
//创建微信对象
$wechatObj = new wechatCallbackapiTest();
//调用验证身份方法（只用一次，用来验证身份）
//$wechatObj->valid();
//响应请求消息
$wechatObj->responseMsg();

class wechatCallbackapiTest
{
    public function valid()
    {
        // 接受随机字符串
        $echoStr = $_GET["echostr"];

        //验证身份算法
        if($this->checkSignature()){
            echo $echoStr;
            exit;
        }
    }

    public function responseMsg()
    {
        //同$_POST用来接收用户发送给腾讯服务器，腾讯服务器推送过来的消息
        $postStr = $GLOBALS["HTTP_RAW_POST_DATA"];

        //extract post data
        if (!empty($postStr)){
                //XML安全过滤
                libxml_disable_entity_loader(true);
                //将腾讯服务器推送的数据转化为对象
                $postObj = simplexml_load_string($postStr, 'SimpleXMLElement', LIBXML_NOCDATA);
                $fromUsername = $postObj->FromUserName; //获取发送者标识
                $toUsername = $postObj->ToUserName;     //获取接受者标识
                $keyword = trim($postObj->Content);     //获取内容
                $time = time();     


                //判断腾讯服务器发送过来的数据类型
                switch ($postObj->MsgType) {
                    
                    case 'text':
                        # code...
                        $content = '文本消息';
                        break;
                    case 'image':
                        # code...
                        $content = '图片消息';
                        break;
                    case 'voice':
                        # code...
                        $content = '语音消息';
                        break;
                    case 'video':
                        $content = '视频消息';
                        # code...
                        break;
                    case 'location':
                        $content = '位置消息';
                        # code...
                        break;
                    case 'link':
                        $content = '链接消息';
                        # code...
                        break;
                    default:
                        # code...
                        $content = '你有瑕疵';
                        break;
                }
                //组装XML响应报文
                $textTpl = "<xml>
                            <ToUserName><![CDATA[%s]]></ToUserName>
                            <FromUserName><![CDATA[%s]]></FromUserName>
                            <CreateTime>%s</CreateTime>
                            <MsgType><![CDATA[%s]]></MsgType>
                            <Content><![CDATA[%s]]></Content>
                            <FuncFlag>0</FuncFlag>
                            </xml>";   
                $msgType = "text";
                //将变量数据替换字符串中的%s
                $resultStr = sprintf($textTpl, $fromUsername, $toUsername, $time, $msgType, $content);
                //响应给腾讯服务器
                echo $resultStr;

        }else {
            echo "";
            exit;
        }
    }
        
    //验证数字签名
    private function checkSignature()
    {
        // 校验TOKEN秘钥
        if (!defined("TOKEN")) {
            throw new Exception('TOKEN is not defined!');
        }
        
        // 接受数字签名
        $signature = $_GET["signature"];
        // 接受时间戳
        $timestamp = $_GET["timestamp"];
        // 接受随机数
        $nonce = $_GET["nonce"];
        
        // 定义$token 获取TOKEN秘钥
        $token = TOKEN;

        // token、timestamp、nonce组成数组
        $tmpArr = array($token, $timestamp, $nonce);
        // use SORT_STRING rule
        //数组排序
        sort($tmpArr, SORT_STRING);
        // 划分成字符串
        $tmpStr = implode( $tmpArr );

        // 通过哈希算法进行加密
        $tmpStr = sha1( $tmpStr );
        
        // 与当前发送过来的数字签名进行比对，成功返回true，否则返回false
        if( $tmpStr == $signature ){
            return true;
        }else{
            return false;
        }
    }
}

?>
