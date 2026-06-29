export const requiredEnv = (name: string): string => {
    const value = process.env[name]

    if (typeof value !== 'string' || value.trim().length === 0) {
        throw new Error(`Missing required environment variable: ${name}`)
    }

    return value
}

export const requiredPemEnv = (name: string): string => {
    return requiredEnv(name).replace(/\\n/g, '\n')
}