import React from 'react'
import { createRoot } from 'react-dom/client'
import { BrowserRouter, Routes, Route, Link, useNavigate } from 'react-router-dom'
import './index.css'

const API = import.meta.env.VITE_API_URL

function useAuth() {
  const [token, setToken] = React.useState(localStorage.getItem('token') || '')
  function save(t){ localStorage.setItem('token', t); setToken(t) }
  return { token, save }
}

function Header() {
  return (
    <header className="sticky top-0 bg-white/80 backdrop-blur border-b z-10">
      <div className="max-w-5xl mx-auto p-3 flex items-center justify-between">
        <Link to="/" className="font-bold text-lg">Admin</Link>
        <nav className="flex gap-4 text-sm">
          <Link to="/">Sản phẩm</Link>
          <Link to="/new">Thêm sản phẩm</Link>
        </nav>
      </div>
    </header>
  )
}

function Login({ onLogin }) {
  const [email, setEmail] = React.useState('admin@demo.com')
  const [password, setPassword] = React.useState('admin123')
  const nav = useNavigate()
  async function submit(e){
    e.preventDefault()
    const res = await fetch(`${API}/auth/login`,{
      method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify({ email, password })
    }).then(r=>r.json())
    if (res.ok) { onLogin(res.token); nav('/') } else alert('Đăng nhập thất bại')
  }
  return (
    <div className="max-w-md mx-auto p-6">
      <form onSubmit={submit} className="bg-white rounded-2xl shadow p-6 space-y-3">
        <div className="text-xl font-bold">Đăng nhập</div>
        <input value={email} onChange={e=>setEmail(e.target.value)} className="w-full border rounded-xl p-2" placeholder="Email" />
        <input type="password" value={password} onChange={e=>setPassword(e.target.value)} className="w-full border rounded-xl p-2" placeholder="Mật khẩu" />
        <button className="w-full bg-blue-600 text-white py-2 rounded-xl">Đăng nhập</button>
      </form>
    </div>
  )
}

function Products({ token }){
  const [items, setItems] = React.useState([])
  React.useEffect(()=>{
    fetch(`${API}/products`).then(r=>r.json()).then(j=> setItems(j.items||[]))
  },[])
  return (
    <div className="max-w-5xl mx-auto p-4 grid md:grid-cols-3 gap-3">
      {items.map(p => (
        <div key={p.id} className="bg-white rounded-2xl shadow">
          <img src={p.imageUrl} className="w-full h-40 object-cover rounded-t-2xl"/>
          <div className="p-3 space-y-1">
            <div className="font-medium">{p.name}</div>
            <div className="text-emerald-600 font-semibold">{(p.price/1000).toFixed(0)}k</div>
            <div className="flex gap-2">
              <a href={`/edit/${p.id}`} className="text-blue-600 text-sm">Sửa</a>
            </div>
          </div>
        </div>
      ))}
    </div>
  )
}

function Upsert({ token, id }){
  const [name, setName] = React.useState('')
  const [price, setPrice] = React.useState(0)
  const [description, setDescription] = React.useState('')
  const [imageUrl, setImageUrl] = React.useState('')
  const nav = useNavigate()

  React.useEffect(()=>{
    if (id) {
      fetch(`${API}/products/${id}`).then(r=>r.json()).then(j=>{
        const p = j.item
        setName(p.name); setPrice(p.price); setDescription(p.description); setImageUrl(p.imageUrl||'')
      })
    }
  }, [id])

  async function uploadFile(e){
    const file = e.target.files?.[0]; if(!file) return
    const form = new FormData(); form.append('file', file)
    const res = await fetch(`${API}/upload`, { method:'POST', headers:{ 'Authorization': `Bearer ${token}` }, body: form }).then(r=>r.json())
    if (res.ok) setImageUrl(res.url || res.key)
    else alert('Upload lỗi')
  }

  async function save(e){
    e.preventDefault()
    const body = { name, description, price: Number(price), imageUrl }
    const method = id ? 'PUT' : 'POST'
    const url = id ? `${API}/admin/products/${id}` : `${API}/admin/products`
    const res = await fetch(url,{
      method, headers:{ 'Content-Type':'application/json', 'Authorization': `Bearer ${token}` },
      body: JSON.stringify(body)
    }).then(r=>r.json())
    if (res.ok) nav('/') ; else alert('Lưu thất bại')
  }

  return (
    <div className="max-w-xl mx-auto p-4">
      <form onSubmit={save} className="bg-white rounded-2xl shadow p-4 space-y-3">
        <div className="text-xl font-bold">{id ? 'Sửa' : 'Thêm'} sản phẩm</div>
        <input value={name} onChange={e=>setName(e.target.value)} className="w-full border rounded-xl p-2" placeholder="Tên"/>
        <input value={price} onChange={e=>setPrice(e.target.value)} className="w-full border rounded-xl p-2" placeholder="Giá (vnd)"/>
        <textarea value={description} onChange={e=>setDescription(e.target.value)} className="w-full border rounded-xl p-2" placeholder="Mô tả"/>
        <div className="space-y-2">
          <div className="text-sm text-gray-600">Ảnh sản phẩm</div>
          {imageUrl && <img src={imageUrl} className="w-40 h-40 object-cover rounded-xl"/>}
          <input type="file" onChange={uploadFile}/>
        </div>
        <button className="w-full bg-emerald-600 text-white py-2 rounded-xl">Lưu</button>
      </form>
    </div>
  )
}

function RouterApp(){
  const auth = useAuth()
  const [loc, setLoc] = React.useState(window.location.pathname)
  React.useEffect(()=>{
    const onPop = () => setLoc(window.location.pathname)
    window.addEventListener('popstate', onPop)
    return () => window.removeEventListener('popstate', onPop)
  },[])

  function route(path){ window.history.pushState({}, '', path); setLoc(path) }

  if (!auth.token) {
    return (
      <BrowserRouter>
        <Header/>
        <Routes>
          <Route path="*" element={<Login onLogin={auth.save}/>}/>
        </Routes>
      </BrowserRouter>
    )
  }

  const editMatch = loc.match(/^\/edit\/(\d+)$/)
  const id = editMatch ? editMatch[1] : null

  return (
    <BrowserRouter>
      <Header/>
      <Routes>
        <Route path="/" element={<Products token={auth.token}/>}/>
        <Route path="/new" element={<Upsert token={auth.token}/>}/>
        <Route path="/edit/:id" element={<Upsert token={auth.token} id={id}/>}/>
      </Routes>
    </BrowserRouter>
  )
}

createRoot(document.getElementById('root')).render(<RouterApp/>)
