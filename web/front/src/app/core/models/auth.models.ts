export interface LoginRequest {
  email: string;
  senha: string;
}

export interface CadastroRequest {
  nomeCompleto: string;
  username: string;
  email: string;
  cpf: string;
  senha: string;
  confirmarSenha: string;
  dataNascimento?: string; // "yyyy-MM-dd"
}

export interface UsuarioResponse {
  idUsuario: number;
  nomeCompleto: string;
  username: string;
  email: string;
  role: string;
}

export interface ErroApi {
  erro: string;
}
