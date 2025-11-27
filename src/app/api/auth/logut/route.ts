// C:\Users\salvaCastro\Desktop\arenaapp-admin\src\app\api\auth\logout\route.ts
import { NextResponse } from 'next/server'
import type { NextRequest } from 'next/server'

export async function POST (_req: NextRequest) {
  const res = NextResponse.json({ message: 'Logout exitoso' })

  // Borrar cookie 'token'
  res.cookies.set('token', '', {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'lax',
    maxAge: 0
  })

  return res
}
