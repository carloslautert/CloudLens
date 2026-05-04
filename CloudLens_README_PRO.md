# CloudLens — AWS Security & Cost Audit

Auditoria automatizada de infraestrutura AWS para identificar riscos de segurança, desperdícios de custo e oportunidades de melhoria.

---

## 🔍 O que é o CloudLens

O CloudLens analisa sua conta AWS de forma segura e identifica:

- Riscos de segurança (acessos públicos, ausência de MFA, etc.)
- Ineficiências de custo (recursos ociosos ou superdimensionados)
- Problemas de governança (falta de logs, organização, etc.)

> A análise é **100% read-only**. Nenhuma alteração é feita no ambiente.

---

## 🔐 Segurança do Acesso

O acesso é feito via **IAM Role com permissões restritas**:

- ✅ Apenas leitura (read-only)
- 🔑 Sem compartilhamento de senha
- ⏱ Tokens temporários (expiram em ~1 hora)
- ❌ Nenhum dado sensível é acessado (arquivos, banco, etc.)
- 🧹 Acesso pode ser revogado a qualquer momento

---

## ⚙️ Como Funciona

1. Você cria uma **IAM Role de auditoria**
2. Compartilha o ARN dessa role
3. O CloudLens executa a análise
4. Você recebe um relatório completo com:
   - Riscos identificados
   - Economia potencial
   - Recomendações práticas

---

## 🧭 Passo a Passo (AWS Console)

### 1. Criar a Policy de Permissões

1. Acesse o IAM → **Policies** → **Create policy**
2. Aba **JSON**
3. Cole a policy abaixo
4. Nome: `CloudLensAuditPolicy`
5. Criar

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "EC2ReadOnly",
      "Effect": "Allow",
      "Action": ["ec2:Describe*"],
      "Resource": "*"
    }
  ]
}
```

---

### 2. Criar a Role de Auditoria

1. IAM → **Roles** → **Create role**
2. Tipo: **Another AWS account**
3. Inserir Account ID fornecido
4. Marcar **Require external ID**
5. Inserir External ID fornecido
6. Selecionar `CloudLensAuditPolicy`
7. Nome: `CloudLensAuditRole`
8. Criar

---

### 3. Enviar o ARN

Exemplo:

arn:aws:iam::123456789012:role/CloudLensAuditRole

---

## ▶️ Execução da Auditoria

python audit.py --role-arn YOUR_ROLE --regions all

---

## ⚠️ Erros Comuns

| Erro | Causa | Como resolver |
|---|---|---|
| AccessDenied | Permissão incorreta | Revisar role |
| Sem resultados | Região errada | Verificar regiões |

---

## 🔌 Revogando o Acesso

1. IAM → Roles  
2. Deletar `CloudLensAuditRole`

---

## 📊 Resumo de Segurança

| Item | Descrição |
|---|---|
| Tipo de acesso | Somente leitura |
| Credenciais | Temporárias |

---

## 🚀 Próximo Passo

Após a auditoria, você recebe um relatório com riscos e oportunidades de melhoria.
