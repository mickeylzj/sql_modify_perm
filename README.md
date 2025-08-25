# Data Permission System

## 项目简介

MySQL数据权限控制系统，支持行级权限过滤和SQL自动改写。通过用户角色和权限规则实现细粒度的数据访问控制。

## 环境配置

### 使用 UV 管理环境

```bash
# 安装UV (如果没有安装)
pip install uv

# 创建虚拟环境
uv venv .venv

# 激活虚拟环境
# Windows
.venv\Scripts\activate
# Linux/Mac  
source .venv/bin/activate

# 安装依赖
uv pip install -r requirements.txt
```

## 数据库表结构

系统共12个表，分为业务表和权限控制表两大类：

### 核心业务表

* **employee** : 员工信息 (user_id, user_name, company_id, role)
* **salary** : 薪资数据 (salary_id, user_id, amount, company_id)
* **company** : 公司信息 (company_id, company_name)
* **age** : 年龄信息 (age_id, user_id, age)

### 权限控制表

* **permission_rules** : 权限规则配置，支持表级/行级权限
* **user_roles** : 角色定义 (管理员、普通员工、部门经理等)
* **user_role_mapping** : 用户角色映射关系
* **permission_logs** : 权限访问日志记录

## 核心功能

### 权限控制流程

1. **用户ID** → 获取用户信息和公司ID
2. **角色识别** → 确定用户有效角色
3. **权限规则** → 匹配适用的权限规则
4. **SQL改写** → 根据规则改写原始SQL
5. **执行查询** → 执行改写后的SQL并返回结果

### 权限规则示例

-- 普通员工只能查看本公司数据
filter_sql: "employee.company_id = $user_company_id"

-- 管理员可以访问所有数据
filter_type: "ALLOW_ALL"

### SQL改写策略

**简单查询** - WHERE条件注入:

-- 原始: SELECT * FROM employee
-- 改写: SELECT * FROM employee WHERE company_id = 1

**复杂查询** - CTE包装:

-- 原始: SELECT e.name, s.amount FROM employee e JOIN salary s ON e.user_id = s.user_id
-- 改写: WITH filtered_employee AS (SELECT * FROM employee WHERE company_id = 1)
     SELECT e.name, s.amount FROM filtered_employee e JOIN salary s ON e.user_id = s.user_id

## 快速开始

### 1. 配置数据库连接

编辑 `config.yaml`:

database:
  host: localhost
  user: root
  password: "123456"
  database: data_permission_system

### 基础功能测试

python main.py

### 安全特性

* **SQL注入防护** : 参数化查询和占位符安全替换
* **权限隔离** : 用户只能访问被授权的数据范围
* **回退机制** : SQL改写失败时的多重回退策略
* **审计日志** : 完整的权限相关操作记录
