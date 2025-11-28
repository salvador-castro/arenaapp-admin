// C:\Users\salvaCastro\Desktop\arenaapp-admin\src\app\api\auth\perfil\route.ts

import { NextResponse } from 'next/server'
import { getDb } from '@/lib/db'
import jwt from 'jsonwebtoken'
import bcrypt from 'bcryptjs'

const JWT_SECRET = process.env.JWT_SECRET || 'supersecretkey123'
const FRONT_ORIGIN = process.env.FRONT_ORIGIN || 'http://localhost:3000'

// helper para agregar CORS siempre
function withCors(jsonBody: any, status = 200) {
  const res = NextResponse.json(jsonBody, { status })
  res.headers.set('Access-Control-Allow-Origin', FRONT_ORIGIN)
  res.headers.set('Access-Control-Allow-Credentials', 'true')
  return res
}

// preflight CORS: OPTIONS /api/auth/perfil
export function OPTIONS() {
  const res = new NextResponse(null, {
    status: 204,
    headers: {
      'Access-Control-Allow-Origin': FRONT_ORIGIN,
      'Access-Control-Allow-Credentials': 'true',
      'Access-Control-Allow-Methods': 'GET,PUT,OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type',
    },
  })
  return res
}

export async function GET(req: Request) {
  try {
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

    const db = getDb()

    const [rows] = await db.execute(
      `
        SELECT 
          id,
          nombre,
          apellido,
          email,
          telefono,
          ciudad,
          pais,
          bio,
          avatar_url
        FROM usuarios
        WHERE id = ?
      `,
      [userId]
    )

    const user = (rows as any[])[0]

    if (!user) {
      return withCors({ error: 'Usuario no encontrado' }, 404)
    }

    return withCors(user, 200)
  } catch (error) {
    console.error('Error en /api/auth/perfil GET:', error)
    return withCors({ error: 'Error en /api/auth/perfil GET' }, 500)
  }
}

export async function PUT(req: Request) {
  try {
    const body = await req.json()

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

    const {
      nombre,
      apellido,
      email,
      telefono,
      ciudad,
      pais,
      bio,
      avatar_url,
      passwordActual,
      passwordNueva,
    } = body

    if (!nombre?.trim() || !apellido?.trim() || !email?.trim()) {
      return withCors(
        { error: 'Nombre, apellido y email son obligatorios.' },
        400
      )
    }

    const db = getDb()

    const telefonoDb = telefono?.toString().trim() || null
    const ciudadDb = ciudad?.toString().trim() || null
    const paisDb = pais?.toString().trim() || null
    const bioDb = bio?.toString().trim() || null
    const avatarDb = avatar_url?.toString().trim() || null

    // ¿quiere cambiar contraseña?
    if (passwordActual || passwordNueva) {
      if (!passwordActual || !passwordNueva) {
        return withCors(
          {
            error:
              'Para cambiar la contraseña completá la contraseña actual y la nueva.',
          },
          400
        )
      }

      const [rows] = await db.execute(
        'SELECT password_hash FROM usuarios WHERE id = ? LIMIT 1',
        [userId]
      )

      const user = (rows as any[])[0]

      if (!user) {
        return withCors({ error: 'Usuario no encontrado' }, 404)
      }

      const passwordHashActual = user.password_hash as string

      const isValid = await bcrypt.compare(passwordActual, passwordHashActual)
      if (!isValid) {
        return withCors(
          { error: 'La contraseña actual no es correcta.' },
          400
        )
      }

      const nuevoHash = await bcrypt.hash(passwordNueva, 10)

      await db.execute(
        `
          UPDATE usuarios
          SET 
            nombre = ?,
            apellido = ?,
            email = ?,
            telefono = ?,
            ciudad = ?,
            pais = ?,
            bio = ?,
            avatar_url = ?,
            password_hash = ?
          WHERE id = ?
        `,
        [
          nombre.trim(),
          apellido.trim(),
          email.trim(),
          telefonoDb,
          ciudadDb,
          paisDb,
          bioDb,
          avatarDb,
          nuevoHash,
          userId,
        ]
      )

      return withCors({
        message: 'Perfil y contraseña actualizados correctamente',
      })
    } else {
      // solo datos de perfil
      await db.execute(
        `
          UPDATE usuarios
          SET 
            nombre = ?,
            apellido = ?,
            email = ?,
            telefono = ?,
            ciudad = ?,
            pais = ?,
            bio = ?,
            avatar_url = ?
          WHERE id = ?
        `,
        [
          nombre.trim(),
          apellido.trim(),
          email.trim(),
          telefonoDb,
          ciudadDb,
          paisDb,
          bioDb,
          avatarDb,
          userId,
        ]
      )

      return withCors({ message: 'Perfil actualizado correctamente' })
    }
  } catch (error) {
    console.error('Error en /api/auth/perfil PUT:', error)
    return withCors({ error: 'Error en /api/auth/perfil PUT' }, 500)
  }
}
