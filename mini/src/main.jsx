import React from 'react'
import { createRoot } from 'react-dom/client'
import { BrowserRouter, Routes, Route, Link, useNavigate, useParams } from 'react-router-dom'
import './index.css'

const API = import.meta.env.VITE_API_URL

function useFetch(url, deps=[]) {
  const [data, setData] = React.useState(null)
  const [loading, setLoading] = React.useState(true)
  React.useEffect(() => {
    let mounted = true
    setLoading(true)
    fetch(url).then(r=>r.json()).then(j=>{ if(mounted) setData(j) }).finally(()=> mounted && setLoading(false))
    return () => mounted = false
  }, deps)
  return { data, loading }
}

function SkeletonCard() {
  return <div className="animate-pulse p-4 rounded-2xl bg-white shadow">
    <div className="h-40 bg-gray-200 rounded-xl mb-3"></div>
    <div className="h-4 bg-gray-200 rounded w-3/4 mb-2"></div>
    <div className="h-4 bg-gray-200 rounded w-1/2"></div>
  </div>
}

function Header() {
  const cartId = localStorage.getItem('cartId')
  return (
    <header className="sticky top-0 bg-white/80 backdrop-blur border-b z-10">
      <div className="max-w-4xl mx-auto p-3 flex items-center justify-between">
        <Link to="/" className="font-bold text-lg">Mini Shop</Link>
        <nav className="flex gap-4 text-sm">
          <Link to="/">Sản phẩm</Link>
          <Link to="/cart">Giỏ hàng</Link>
        </nav>
      </div>
    </header>
  )
}

function Home() {
  const { data, loading } = useFetch(`${API}/products`, [])
  return (
    <div className="max-w-4xl mx-auto p-3 grid grid-cols-2 md:grid-cols-3 gap-3">
      {loading && Array.from({length:6}).map((_,i)=><SkeletonCard key={i}/>)}
      {!loading && data?.items?.map(p => (
        <Link key={p.id} to={`/product/${p.id}`} className="bg-white rounded-2xl shadow hover:shadow-md transition">
          <img src={p.imageUrl} alt={p.name} className="w-full h-40 object-cover rounded-t-2xl"/>
          <div className="p-3">
            <div className="font-medium">{p.name}</div>
            <div className="text-emerald-600 font-semibold">{(p.price/1000).toFixed(0)}k</div>
          </div>
        </Link>
      ))}
    </div>
  )
}

function Product() {
  const { id } = useParams()
  const { data, loading } = useFetch(`${API}/products/${id}`, [id])
  const nav = useNavigate()

  async function ensureCart() {
    let cid = localStorage.getItem('cartId')
    if (!cid) {
      const res = await fetch(`${API}/cart`, { method:'POST'}).then(r=>r.json())
      cid = res.cartId
      localStorage.setItem('cartId', cid)
    }
    return cid
  }

  async function addToCart() {
    const cid = await ensureCart()
    await fetch(`${API}/cart/${cid}/items`,{
      method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify({ productId: Number(id), qty: 1 })
    })
    nav('/cart')
  }

  if (loading) return <div className="max-w-3xl mx-auto p-4"><SkeletonCard/></div>
  const p = data?.item
  return (
    <div className="max-w-3xl mx-auto p-4">
      <div className="bg-white rounded-2xl shadow overflow-hidden">
        <img src={p.imageUrl} className="w-full h-64 object-cover"/>
        <div className="p-4 space-y-2">
          <div className="text-xl font-bold">{p.name}</div>
          <div className="text-emerald-600 font-semibold">{(p.price/1000).toFixed(0)}k</div>
          <p className="text-gray-600">{p.description}</p>
          <button onClick={addToCart} className="mt-2 bg-blue-600 text-white px-4 py-2 rounded-xl active:scale-95 transition">Thêm giỏ</button>
        </div>
      </div>
    </div>
  )
}

function Cart() {
  const [cart, setCart] = React.useState(null)

  async function load() {
    const cid = localStorage.getItem('cartId')
    if (!cid) return
    const data = await fetch(`${API}/cart/${cid}`).then(r=>r.json())
    setCart(data.cart)
  }
  React.useEffect(()=>{load()},[])

  async function checkout() {
    const cid = localStorage.getItem('cartId')
    if (!cid) return alert('Chưa có giỏ nào')
    const name = prompt('Tên người nhận?') || 'Khách'
    const phone = prompt('SĐT?') || '0900000000'
    const address = prompt('Địa chỉ?') || 'TP.HCM'
    const res = await fetch(`${API}/checkout`,{
      method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify({ cartId: cid, name, phone, address })
    }).then(r=>r.json())
    if (res.ok) window.location.href = res.payment_url
    else alert('Checkout lỗi')
  }

  const total = cart?.items?.reduce((s,i)=> s + i.qty * i.product.price, 0) || 0

  return (
    <div className="max-w-3xl mx-auto p-4">
      <div className="bg-white rounded-2xl shadow">
        <div className="p-4 border-b font-bold">Giỏ hàng</div>
        <div className="p-4 space-y-3">
          {!cart && <div className="text-gray-500">Chưa có sản phẩm</div>}
          {cart && cart.items.map(ci => (
            <div key={ci.id} className="flex items-center gap-3">
              <img src={ci.product.imageUrl} className="w-16 h-16 rounded-xl object-cover"/>
              <div className="flex-1">
                <div className="font-medium">{ci.product.name}</div>
                <div className="text-sm text-gray-500">x{ci.qty}</div>
              </div>
              <div className="font-semibold">{(ci.product.price/1000).toFixed(0)}k</div>
            </div>
          ))}
          <div className="border-t pt-3 flex justify-between">
            <div className="text-gray-600">Tổng</div>
            <div className="font-bold">{(total/1000).toFixed(0)}k</div>
          </div>
          <button onClick={checkout} className="w-full bg-emerald-600 text-white py-3 rounded-xl active:scale-95">Thanh toán</button>
        </div>
      </div>
    </div>
  )
}

function App() {
  return (
    <BrowserRouter>
      <Header/>
      <Routes>
        <Route path="/" element={<Home/>}/>
        <Route path="/product/:id" element={<Product/>}/>
        <Route path="/cart" element={<Cart/>}/>
      </Routes>
    </BrowserRouter>
  )
}

createRoot(document.getElementById('root')).render(<App/>)
