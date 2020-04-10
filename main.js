const express = require('express');
var bodyParser = require('body-parser');
const expressJWT = require('express-jwt');

//导入配置文件
const setting = require('./setting');
//导入 token 校验文件
const verify = require('./verify');
const app = express();

//bodyParser 使用bodyParser 解析post请求传递过来的参数
app.use(bodyParser.json());

//跨域配置
app.use((req, res, next) => {
  res.append("Access-Control-Allow-Origin", "*");
  res.append("Access-Control-Allow-Origin-Type", "*");
  next();
})

// 使用expressJWT 验证token是否过期
app.use(expressJWT({
  secret: setting.token.signKey // 签名的密钥 或 PublicKey
}).unless({ // 设置并规定哪些路由不用验证 token
  path: ['/api/hello'] // 指定路径不经过 Token 解析
}));


//当token失效返回提示信息 时间过期了执行这一条
app.use((err, req, res, next) => {
    // console.log(req);
  if (err.status === 401) {
    return res.json({
      status: err.status,
      msg: 'token失效',
      error: err.name + ':' + err.message
    })
  }
});

// post 请求
app.post('/api/hello', (req, res) => {
  verify.setToken(req.body.name,req.body.password).then(async(token) => {
    return res.json({
      status: 0,
      msg: 'success',
      token,
      signTime: setting.token.signTime
    })
  });
})

// get 请求
app.get('/api/info', async(req, res) => {
  let data = await verify.getToken(req.query.token);
  // 有些请求是需要登录状态的 所以验证token
  // 验证 data.state >>> true Or false
  data.state ?
    (res.json({
      status:0,
      msg: '可以访问'
    })) :
    (res.json({
      status:-1,
      msg: '请登录'
    }));
});

app.listen(5000, () => {
  console.log(`你的本地服务 localhost:5000`);
})
