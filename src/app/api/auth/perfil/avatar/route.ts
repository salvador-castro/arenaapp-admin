// C:\Users\salvaCastro\Desktop\arenaapp-admin\src\app\api\auth\perfil\avatar\route.ts

import { NextResponse } from 'next/server'
import { getDb } from '@/lib/db'
import jwt from 'jsonwebtoken'
import fs from 'fs'
import path from 'path'

export const runtime = 'nodejs' // necesitamos fs/path

const JWT_SECRET = process.env.JWT_SECRET || 'supersecretkey123'
const FRONT_ORIGIN = process.env.FRONT_ORIGIN || 'http://localhost:3000'

// helper para CORS
function withCors(jsonBody: any, status = 200) {
  const res = NextResponse.json(jsonBody, { status })
  res.headers.set('Access-Control-Allow-Origin', FRONT_ORIGIN)
  res.headers.set('Access-Control-Allow-Credentials', 'true')
  return res
}

// Preflight: OPTIONS /api/auth/perfil/avatar
export function OPTIONS() {
  return new NextResponse(null, {
    status: 204,
    headers: {
      'Access-Control-Allow-Origin': FRONT_ORIGIN,
      'Access-Control-Allow-Credentials': 'true',
      'Access-Control-Allow-Methods': 'POST,OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type',
    },
  })
}

export async function POST(req: Request) {
  try {
    // 🔐 leer cookie "token"
    const cookie = req.headers.get('cookie') || ''
    const token = cookie
      .split(';')
      .find(part => part.trim().startsWith('token='))
      ?.split('=')[1]

    if (!token) {
      return withCors({ error: 'No autenticado' }, 401)
    }

    const payload: any = jwt.verify(token, JWT_SECRET)
    const userId = payload.userId

    // 📦 leer archivo del form-data
    const formData = await req.formData()
    const file = formData.get('avatar')

    if (!file || !(file instanceof File)) {
      return withCors(
        { error: 'No se recibió ningún archivo' },
        400
      )
    }

    const mime = file.type
    const allowed = ['image/png', 'image/jpeg', 'image/jpg', 'image/webp']

    if (!allowed.includes(mime)) {
      return withCors(
        { error: 'Formato de imagen no permitido' },
        400
      )
    }

    const bytes = await file.arrayBuffer()
    const buffer = Buffer.from(bytes)

    // límite 2 MB
    if (buffer.length > 2 * 1024 * 1024) {
      return withCors(
        { error: 'La imagen supera el tamaño máximo (2 MB)' },
        400
      )
    }

    let ext = 'jpg'
    if (mime === 'image/png') ext = 'png'
    if (mime === 'image/webp') ext = 'webp'

    // 📁 carpeta destino: public/uploads/avatars
    const uploadsDir = path.join(
      process.cwd(),
      'public',
      'uploads',
      'avatars'
    )

    await fs.promises.mkdir(uploadsDir, { recursive: true })

    const filename = `avatar-${userId}-${Date.now()}.${ext}`
    const filePath = path.join(uploadsDir, filename)

    await fs.promises.writeFile(filePath, buffer)

    const avatarUrl = `/uploads/avatars/${filename}`

    // 💾 guardar URL en la BBDD
    const db = getDb()
    await db.execute(
      'UPDATE usuarios SET avatar_url = ? WHERE id = ?',
      [avatarUrl, userId]
    )

    return withCors({ avatar_url: avatarUrl })
  } catch (error) {
    console.error('Error en /api/auth/perfil/avatar:', error)
    return withCors(
      { error: 'Error al subir la foto de perfil' },
      500
    )
  }
}
