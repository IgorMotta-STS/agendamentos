import express from 'express';
import dotenv from 'dotenv';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import cors from 'cors';
import { createClient } from '@supabase/supabase-js';

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'se7_terminais_jwt_secret_2026';

// =============================
// CONFIGURAÇÃO DO SUPABASE
// =============================
const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_KEY = process.env.SUPABASE_KEY;

if (!SUPABASE_URL || !SUPABASE_KEY) {
  console.error("ERRO CRÍTICO: Configurações do Supabase ausentes no arquivo .env");
}

const supabase = createClient(SUPABASE_URL, SUPABASE_KEY);

// =============================
// MIDDLEWARES INICIAIS
// =============================
app.use(cors());
app.use(express.json());

// =============================
// FUNÇÕES AUXILIARES DE NEGÓCIO
// =============================
async function registrarLog(usuarioEmail, acao) {
  try {
    await supabase.from('logs').insert([
      // CORRIGIDO: dataHora para datahora
      { usuario: usuarioEmail, acao, datahora: new Date().toISOString() }
    ]);
  } catch (error) {
    console.error('Erro ao registrar log no Supabase:', error.message);
  }
}

async function criarAdminPadrao() {
  try {
    const { data: user } = await supabase
      .from('users')
      .select('*')
      .eq('email', 'admin@empresa.com')
      .maybeSingle();

    if (!user) {
      const senhaHash = await bcrypt.hash('123456', 10);
      await supabase.from('users').insert([
        {
          nome: 'Administrador',
          email: 'admin@empresa.com',
          senha: senhaHash,
          perfil: 'admin',
          ativo: true
        }
      ]);
      console.log('Usuário administrador verificado/criado no Supabase: admin@empresa.com / 123456');
    }
  } catch (error) {
    console.error('Erro ao verificar administrador padrão:', error.message);
  }
}

// Middleware de validação do token JWT
function autenticarToken(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ erro: 'Token não informado.' });
  }

  const token = authHeader.split(' ')[1];
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.usuario = decoded;
    next();
  } catch (error) {
    return res.status(401).json({ erro: 'Token inválido ou expirado.' });
  }
}

function somenteAdmin(req, res, next) {
  if (req.usuario.perfil !== 'admin') {
    return res.status(403).json({ erro: 'Acesso restrito ao administrador.' });
  }
  next();
}

// =============================
// ROTAS DE AUTENTICAÇÃO E USUÁRIO
// =============================
app.post('/api/cadastro', async (req, res) => {
  try {
    const { nome, email, senha } = req.body;
    const perfilSeguro = 'usuario';

    if (!nome || !email || !senha) {
      return res.status(400).json({ erro: 'Nome, e-mail e senha são obrigatórios.' });
    }

    const { data: userExiste } = await supabase
      .from('users')
      .select('*')
      .eq('email', email.toLowerCase())
      .maybeSingle();

    if (userExiste) {
      return res.status(400).json({ erro: 'E-mail já cadastrado.' });
    }

    const senhaHash = await bcrypt.hash(senha, 10);
    
    const { error } = await supabase.from('users').insert([
      { nome, email: email.toLowerCase(), senha: senhaHash, perfil: perfilSeguro, ativo: true }
    ]);

    if (error) throw error;

    await registrarLog(email, 'Cadastro de usuário');
    res.status(201).json({ mensagem: 'Usuário cadastrado com sucesso.' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ erro: 'Erro interno no servidor ao cadastrar.' });
  }
});

app.post('/api/login', async (req, res) => {
  try {
    const { email, usuario, senha } = req.body;
    const login = email || usuario;

    if (!login || !senha) {
      return res.status(400).json({ erro: 'Login e senha são obrigatórios.' });
    }

    const { data: user } = await supabase
      .from('users')
      .select('*')
      .eq('email', login.toLowerCase())
      .maybeSingle();

    if (!user) {
      return res.status(401).json({ erro: 'Usuário não encontrado.' });
    }

    if (!user.ativo) {
      return res.status(403).json({ erro: 'Usuário inativo.' });
    }

    const senhaValida = await bcrypt.compare(senha, user.senha);
    if (!senhaValida) {
      return res.status(401).json({ erro: 'Senha inválida.' });
    }

    const token = jwt.sign(
      { id: user.id, nome: user.nome, email: user.email, perfil: user.perfil },
      JWT_SECRET,
      { expiresIn: '8h' }
    );

    await registrarLog(user.email, 'Login realizado');

    res.json({
      token,
      usuario: { id: user.id, nome: user.nome, email: user.email, perfil: user.perfil, ativo: user.ativo }
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ erro: 'Erro interno no servidor ao autenticar.' });
  }
});

app.put('/api/perfil', autenticarToken, async (req, res) => {
  try {
    const { senhaNova } = req.body;
    
    if (!senhaNova || senhaNova.length < 6) {
      return res.status(400).json({ erro: 'A senha deve ter no mínimo 6 caracteres.' });
    }

    const senhaHash = await bcrypt.hash(senhaNova, 10);

    const { error } = await supabase
      .from('users')
      .update({ senha: senhaHash })
      .eq('id', req.usuario.id);

    if (error) throw error;

    await registrarLog(req.usuario.email, 'Alterou a própria senha de acesso');
    res.json({ mensagem: 'Senha atualizada com sucesso.' });
  } catch (error) {
    console.error('Erro ao atualizar perfil:', error);
    res.status(500).json({ erro: 'Erro interno ao atualizar perfil.' });
  }
});

// ROTA PÚBLICA DE RASTREIO
app.get('/api/rastreio/:codigo', async (req, res) => {
  try {
    const { codigo } = req.params;
    
    // CORRIGIDO: dataHora e atualizadoEm para datahora e atualizadoem
    let query = supabase.from('agendamentos').select('id, cliente, transportadora, produto, status, datahora, atualizadoem');
    
    if (!isNaN(codigo)) {
      query = query.or(`id.eq.${codigo},di.eq.${codigo}`);
    } else {
      query = query.eq('di', codigo);
    }

    const { data, error } = await query.maybeSingle();

    if (error) throw error;
    if (!data) return res.status(404).json({ erro: 'Carga não encontrada.' });

    res.json(data);
  } catch (error) {
    console.error('Erro no rastreio:', error);
    res.status(500).json({ erro: 'Erro interno ao buscar rastreio.' });
  }
});

// =============================
// ROTAS DE AGENDAMENTOS
// =============================
app.get('/api/agendamentos', autenticarToken, async (req, res) => {
  try {
    let query = supabase.from('agendamentos').select('*');
    
    if (req.usuario.perfil !== 'admin') {
      // CORRIGIDO: usuarioId para usuarioid
      query = query.eq('usuarioid', req.usuario.id);
    }

    const { data: agendamentos, error } = await query;
    if (error) throw error;

    res.json(agendamentos || []);
  } catch (error) {
    res.status(500).json({ erro: 'Erro ao buscar agendamentos.' });
  }
});

app.post('/api/agendamentos', autenticarToken, async (req, res) => {
  try {
    // FILTRO MÁGICO
    const bodyMinusculo = {};
    for (const key in req.body) {
      bodyMinusculo[key.toLowerCase()] = req.body[key];
    }

    const payload = {
      ...bodyMinusculo,
      usuarioid: req.usuario.id,
      usuarionome: req.usuario.nome,
      criadoem: new Date().toISOString()
    };

    const { data, error } = await supabase
      .from('agendamentos')
      .insert([payload])
      .select()
      .single();

    if (error) throw error;

    await registrarLog(req.usuario.email, `Criou agendamento #${data.id}`);
    res.status(201).json(data);
  } catch (error) {
    console.error('ERRO NO SUPABASE:', error);
    res.status(500).json({ erro: 'Erro interno no servidor ao criar agendamento.' });
  }
});

app.put('/api/agendamentos/:id', autenticarToken, async (req, res) => {
  try {
    const { id } = req.params;

    const { data: agendamento } = await supabase
      .from('agendamentos')
      .select('*')
      .eq('id', id)
      .maybeSingle();

    if (!agendamento) {
      return res.status(404).json({ erro: 'Agendamento não encontrado.' });
    }

    // CORRIGIDO: agendamento.usuarioId para agendamento.usuarioid
    if (req.usuario.perfil !== 'admin' && agendamento.usuarioid !== req.usuario.id) {
      return res.status(403).json({ erro: 'Acesso negado.' });
    }

    // FILTRO MÁGICO
    const bodyMinusculo = {};
    for (const key in req.body) {
      bodyMinusculo[key.toLowerCase()] = req.body[key];
    }

    const payloadAtualizacao = {
      ...bodyMinusculo,
      atualizadoem: new Date().toISOString()
    };

    const { data, error } = await supabase
      .from('agendamentos')
      .update(payloadAtualizacao)
      .eq('id', id)
      .select()
      .single();

    if (error) throw error;

    await registrarLog(req.usuario.email, `Editou agendamento #${id}`);
    res.json(data);
  } catch (error) {
    console.error('ERRO NO SUPABASE:', error);
    res.status(500).json({ erro: 'Erro interno no servidor ao atualizar agendamento.' });
  }
});

app.delete('/api/agendamentos/:id', autenticarToken, async (req, res) => {
  try {
    const { id } = req.params;

    const { data: agendamento } = await supabase
      .from('agendamentos')
      .select('*')
      .eq('id', id)
      .maybeSingle();

    if (!agendamento) {
      return res.status(404).json({ erro: 'Agendamento não encontrado.' });
    }

    // CORRIGIDO: agendamento.usuarioId para agendamento.usuarioid
    if (req.usuario.perfil !== 'admin' && agendamento.usuarioid !== req.usuario.id) {
      return res.status(403).json({ erro: 'Acesso negado.' });
    }

    const { error } = await supabase.from('agendamentos').delete().eq('id', id);
    if (error) throw error;

    await registrarLog(req.usuario.email, `Excluiu agendamento #${id}`);
    res.json({ mensagem: 'Agendamento excluído com sucesso.' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ erro: 'Erro interno no servidor ao excluir agendamento.' });
  }
});

// =============================
// ROTAS ADMINISTRATIVAS
// =============================
app.get('/api/users', autenticarToken, somenteAdmin, async (req, res) => {
  try {
    const { data: users, error } = await supabase
      .from('users')
      .select('id, nome, email, perfil, ativo');

    if (error) throw error;
    res.json(users || []);
  } catch (error) {
    res.status(500).json({ erro: 'Erro ao buscar usuários.' });
  }
});

app.put('/api/users/:id', autenticarToken, somenteAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const { perfil, ativo } = req.body;

    const updates = {};
    if (perfil !== undefined) updates.perfil = perfil;
    if (ativo !== undefined) updates.ativo = ativo;

    const { error } = await supabase.from('users').update(updates).eq('id', id);
    if (error) throw error;

    await registrarLog(req.usuario.email, `Alterou permissões do usuário #${id}`);
    res.json({ mensagem: 'Usuário atualizado com sucesso.' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ erro: 'Erro interno no servidor ao atualizar perfil.' });
  }
});

app.get('/api/logs', autenticarToken, somenteAdmin, async (req, res) => {
  try {
    const { data: logs, error } = await supabase
      .from('logs')
      .select('*')
      // CORRIGIDO: dataHora para datahora
      .order('datahora', { ascending: false });

    if (error) throw error;
    res.json(logs || []);
  } catch (error) {
    res.status(500).json({ erro: 'Erro ao buscar logs.' });
  }
});

app.get('/', (req, res) => {
  res.json({ mensagem: 'API SE7 Terminais integrada com a nuvem do Supabase rodando perfeitamente.' });
});

// =============================
// INICIALIZAÇÃO
// =============================
criarAdminPadrao().then(() => {
  app.listen(PORT, () => {
    console.log(`Servidor rodando em nuvem híbrida na porta http://localhost:${PORT}`);
  });
});