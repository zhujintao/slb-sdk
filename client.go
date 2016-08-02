
package slb

import (
	"net/url"
	"fmt"
	"time"
	"crypto/hmac"
	"hash"
	"crypto/sha1"
	"io"
	"encoding/base64"
	"net/http"
	"io/ioutil"
)


type Client struct {
	commparame url.Values
	parameters url.Values
	slburl string
	accessKeySecret string
}

func SetDefault(accessKeyId,accessKeySecret string) *Client {
	return &Client{
		commparame:map[string][]string{
			"Format":{"json"},
			"Version":{"2014-05-15"},
			"AccessKeyId":{accessKeyId},
			"SignatureMethod":{"HMAC-SHA1"},
			"SignatureVersion":{"1.0"},
		},
		slburl:"http://slb.aliyuncs.com",
		accessKeySecret:accessKeySecret,
	}
}

func (c *Client) clear() {
	t := time.Now().UTC()
  	tm:= t.Format("2006-01-02T15:04:05Z")
	c.parameters=url.Values{}
	c.parameters.Add("Timestamp",tm)
	c.parameters.Add("SignatureNonce",tm)
	for k,v:= range c.commparame{
		c.parameters[k]=v
	}
}

func (c *Client) do() ([]byte,error)  {

	u,_:=url.Parse(c.slburl)
	u.RawQuery=c.parameters.Encode()
	s:="GET&%2F&" + url.QueryEscape(u.RawQuery)
	h := hmac.New(func() hash.Hash { return sha1.New() }, []byte(c.accessKeySecret + "&"))
	io.WriteString(h, s)
	signedStr := base64.StdEncoding.EncodeToString(h.Sum(nil))
	signature := "&"+url.QueryEscape("Signature") + "=" + url.QueryEscape(signedStr)
	resp,_:=http.Get(u.String()+signature)
	defer resp.Body.Close()
	d,err :=ioutil.ReadAll(resp.Body)
	return d,err

}

func (c *Client) DescribeLoadBalancers(region string){
	c.clear()
	c.parameters.Add("Action","DescribeLoadBalancers")
	c.parameters.Add("RegionId",region)
	s,err:=c.do()
	if err == nil {
		fmt.Println(string(s))
	}
}

func (c *Client) SetBackendServers(id,list string){
	c.clear()
	c.parameters.Add("Action","SetBackendServers")
	c.parameters.Add("LoadBalancerId",id)
	c.parameters.Add("BackendServers",list)

}







func (c *Client) Uncondition (action string,other map[string][]string){
	c.clear()
	c.parameters.Add("Action",action)
	for k,v:= range other{
		c.parameters[k]=v
	}
	s,err:=c.do()
	if err == nil {
		fmt.Println(string(s))
	}
}








