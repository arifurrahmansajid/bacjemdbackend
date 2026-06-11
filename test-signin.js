const data = JSON.stringify({ email: 'admin@hopelink.com', password: 'Admin@12345' });
fetch('http://localhost:5000/api/v1/auth/sign-in', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: data
}).then(res => {
  console.log('Status:', res.status);
  return res.json();
}).then(console.log).catch(console.error);
