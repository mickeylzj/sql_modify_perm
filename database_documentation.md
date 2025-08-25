# data_permission_system 数据库结构文档

**生成时间**: 2025-08-25T15:04:07.861895
**表总数**: 12

## 数据库概览

| 表名 | 数据行数 | 表大小(MB) | 主要用途 |
|------|----------|------------|----------|
| age | 26 | 0.03 | 年龄信息 |
| company | 9 | 0.02 | 公司信息 |
| employee | 26 | 0.03 | 员工基础信息 |
| permission | 0 | 0.03 | 业务数据表 |
| permission_log | 2 | 0.02 | 业务数据表 |
| permission_logs | 691 | 0.23 | 权限访问日志 |
| permission_rules | 10 | 0.02 | 权限规则配置 |
| role | 2 | 0.02 | 业务数据表 |
| salary | 26 | 0.05 | 薪资数据 |
| user_role | 0 | 0.02 | 业务数据表 |
| user_role_mapping | 26 | 0.03 | 用户角色映射 |
| user_roles | 4 | 0.03 | 用户角色定义 |

## 详细表结构

### age

**数据行数**: 26
**表大小**: 0.03 MB

#### 字段结构

| 字段名 | 类型 | 是否为空 | 默认值 | 主键 | 自增 | 备注 |
|--------|------|----------|--------|------|------|------|
| age_id | INTEGER | ❌ | - | ❌ | ✅ | None |
| user_id | INTEGER | ❌ | - | ❌ | ❌ | None |
| age | INTEGER | ❌ | - | ❌ | ❌ | None |

#### 索引信息
- **user_id**: 普通索引，字段: user_id

#### 外键关系
- **age_ibfk_1**: user_id → employee.user_id

#### 样本数据

| age_id | user_id | age |
|---|---|---|
| 1 | 1 | 30 |
| 2 | 2 | 35 |
| 3 | 3 | 28 |

### company

**数据行数**: 9
**表大小**: 0.02 MB

#### 字段结构

| 字段名 | 类型 | 是否为空 | 默认值 | 主键 | 自增 | 备注 |
|--------|------|----------|--------|------|------|------|
| company_id | INTEGER | ❌ | - | ❌ | ✅ | None |
| company_name | VARCHAR(100) | ❌ | - | ❌ | ❌ | None |

#### 样本数据

| company_id | company_name |
|---|---|
| 1 | 兴业总公司 |
| 2 | 上海分公司 |
| 3 | 北京分公司 |

### employee

**数据行数**: 26
**表大小**: 0.03 MB

#### 字段结构

| 字段名 | 类型 | 是否为空 | 默认值 | 主键 | 自增 | 备注 |
|--------|------|----------|--------|------|------|------|
| user_id | INTEGER | ❌ | - | ❌ | ✅ | None |
| user_name | VARCHAR(100) | ❌ | - | ❌ | ❌ | None |
| company_id | INTEGER | ❌ | - | ❌ | ❌ | None |
| role | VARCHAR(50) | ❌ | - | ❌ | ❌ | None |

#### 索引信息
- **company_id**: 普通索引，字段: company_id

#### 外键关系
- **employee_ibfk_1**: company_id → company.company_id

#### 样本数据

| user_id | user_name | company_id | role |
|---|---|---|---|
| 1 | 张三 | 1 | 普通员工 |
| 2 | 李四 | 2 | 管理员 |
| 3 | 王五 | 3 | 普通员工 |

### permission

**数据行数**: 0
**表大小**: 0.03 MB

#### 字段结构

| 字段名 | 类型 | 是否为空 | 默认值 | 主键 | 自增 | 备注 |
|--------|------|----------|--------|------|------|------|
| permission_id | INTEGER | ❌ | - | ❌ | ✅ | None |
| role_id | INTEGER | ❌ | - | ❌ | ❌ | None |
| table_name | VARCHAR(100) | ❌ | - | ❌ | ❌ | None |
| access_level | VARCHAR(50) | ❌ | - | ❌ | ❌ | None |

#### 索引信息
- **role_id**: 普通索引，字段: role_id

#### 外键关系
- **permission_ibfk_1**: role_id → role.role_id

### permission_log

**数据行数**: 2
**表大小**: 0.02 MB

#### 字段结构

| 字段名 | 类型 | 是否为空 | 默认值 | 主键 | 自增 | 备注 |
|--------|------|----------|--------|------|------|------|
| log_id | INTEGER | ❌ | - | ❌ | ✅ | None |
| user_id | INTEGER | ❌ | - | ❌ | ❌ | None |
| original_sql | TEXT | ✅ | - | ❌ | ❌ | None |
| modified_sql | TEXT | ✅ | - | ❌ | ❌ | None |
| table_names | TEXT | ✅ | - | ❌ | ❌ | None |
| execution_result | VARCHAR(50) | ✅ | - | ❌ | ❌ | None |
| execution_time | FLOAT | ✅ | - | ❌ | ❌ | None |
| error_message | TEXT | ✅ | - | ❌ | ❌ | None |
| created_at | DATETIME | ✅ | - | ❌ | ❌ | None |

#### 样本数据

| log_id | user_id | original_sql | modified_sql | table_names | execution_result | execution_time | error_message | created_at |
|---|---|---|---|---|---|---|---|---|
| 1 | 1 | SELECT e.user_name, s.amoun... | None | [] | error | 0.000307322 | SQL安全检查失败: ['DROP', 'DELETE... | 2025-08-18 07:41:22 |
| 2 | 1 | SELECT e.user_name, s.amoun... | None | [] | error | 0.0 | SQL安全检查失败: ['DROP', 'DELETE... | 2025-08-18 07:41:37 |

### permission_logs

**数据行数**: 691
**表大小**: 0.23 MB

#### 字段结构

| 字段名 | 类型 | 是否为空 | 默认值 | 主键 | 自增 | 备注 |
|--------|------|----------|--------|------|------|------|
| log_id | INTEGER | ❌ | - | ❌ | ✅ | None |
| user_id | INTEGER | ❌ | - | ❌ | ❌ | 用户ID |
| original_sql | TEXT | ✅ | - | ❌ | ❌ | 原始SQL |
| modified_sql | TEXT | ✅ | - | ❌ | ❌ | 修改后SQL |
| table_names | TEXT | ✅ | - | ❌ | ❌ | 涉及的表名，JSON格式 |
| execution_result | VARCHAR(20) | ✅ | - | ❌ | ❌ | 执行结果：success/failed/denied |
| execution_time | INTEGER | ✅ | - | ❌ | ❌ | 执行时间（毫秒） |
| error_message | TEXT | ✅ | - | ❌ | ❌ | 错误信息 |
| created_at | DATETIME | ✅ | - | ❌ | ❌ | None |

#### 样本数据

| log_id | user_id | original_sql | modified_sql | table_names | execution_result | execution_time | error_message | created_at |
|---|---|---|---|---|---|---|---|---|
| 1 | 1 | SELECT * FROM employee | SELECT * FROM employee WHER... | ["employee"] | success | 25 | None | 2025-08-15 05:48:37 |
| 2 | 1 | SELECT * FROM employee | SELECT * FROM employee WHER... | ["employee"] | success | 25 | None | 2025-08-15 05:48:53 |
| 3 | 1 | SELECT * FROM employee | SELECT * FROM employee WHER... | ["employee"] | success | 30 | None | 2025-08-15 05:57:54 |

### permission_rules

**数据行数**: 10
**表大小**: 0.02 MB

#### 字段结构

| 字段名 | 类型 | 是否为空 | 默认值 | 主键 | 自增 | 备注 |
|--------|------|----------|--------|------|------|------|
| rule_id | INTEGER | ❌ | - | ❌ | ✅ | 规则ID |
| rule_name | VARCHAR(100) | ❌ | - | ❌ | ❌ | 规则名称 |
| table_name | VARCHAR(100) | ❌ | - | ❌ | ❌ | 表名，*表示所有表 |
| permission_type | ENUM | ❌ | - | ❌ | ❌ | 权限类型 |
| filter_type | ENUM | ❌ | - | ❌ | ❌ | 过滤类型 |
| filter_sql | TEXT | ✅ | - | ❌ | ❌ | 自定义过滤SQL，支持占位符 |
| target_roles | TEXT | ✅ | - | ❌ | ❌ | 适用角色列表，JSON格式存储 |
| is_active | TINYINT | ✅ | - | ❌ | ❌ | 是否启用 |
| priority | INTEGER | ✅ | - | ❌ | ❌ | 优先级，数字越大优先级越高 |
| created_at | DATETIME | ✅ | - | ❌ | ❌ | 创建时间 |
| updated_at | DATETIME | ✅ | - | ❌ | ❌ | 更新时间 |
| description | TEXT | ✅ | - | ❌ | ❌ | 规则描述 |
| view_template | TEXT | ✅ | - | ❌ | ❌ | 权限视图模板 |

#### 样本数据

| rule_id | rule_name | table_name | permission_type | filter_type | filter_sql | target_roles | is_active | priority | created_at | updated_at | description | view_template |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| 1 | 管理员全表访问 | * | TABLE_LEVEL | ALLOW_ALL | None | ["管理员"] | 1 | 100 | 2025-08-15 05:48:36 | 2025-08-25 06:56:43 | 管理员可以访问所有表的所有数据，不受任何限制 | None |
| 2 | 普通员工薪水行级权限 | salary | ROW_LEVEL | CUSTOM_SQL | salary.company_id = $user_c... | ["普通员工"] | 1 | 10 | 2025-08-15 05:48:36 | 2025-08-25 06:56:43 | 普通员工只能查看自己分公司的薪水数据 | None |
| 3 | 普通员工员工信息行级权限 | employee | ROW_LEVEL | CUSTOM_SQL | employee.company_id = $user... | ["普通员工"] | 1 | 10 | 2025-08-15 05:48:36 | 2025-08-25 06:56:43 | 普通员工只能查看自己分公司的员工信息 | None |

### role

**数据行数**: 2
**表大小**: 0.02 MB

#### 字段结构

| 字段名 | 类型 | 是否为空 | 默认值 | 主键 | 自增 | 备注 |
|--------|------|----------|--------|------|------|------|
| role_id | INTEGER | ❌ | - | ❌ | ✅ | None |
| role_name | VARCHAR(100) | ❌ | - | ❌ | ❌ | None |
| permissions | TEXT | ✅ | - | ❌ | ❌ | None |

#### 样本数据

| role_id | role_name | permissions |
|---|---|---|
| 1 | 管理员 | salary:read,write;employee:... |
| 2 | 普通员工 | salary:read;employee:read; |

### salary

**数据行数**: 26
**表大小**: 0.05 MB

#### 字段结构

| 字段名 | 类型 | 是否为空 | 默认值 | 主键 | 自增 | 备注 |
|--------|------|----------|--------|------|------|------|
| salary_id | INTEGER | ❌ | - | ❌ | ✅ | None |
| user_id | INTEGER | ❌ | - | ❌ | ❌ | None |
| amount | DECIMAL(10, 2) | ❌ | - | ❌ | ❌ | None |
| company_id | INTEGER | ❌ | - | ❌ | ❌ | None |

#### 索引信息
- **company_id**: 普通索引，字段: company_id
- **user_id**: 普通索引，字段: user_id

#### 外键关系
- **salary_ibfk_1**: user_id → employee.user_id
- **salary_ibfk_2**: company_id → company.company_id

#### 样本数据

| salary_id | user_id | amount | company_id |
|---|---|---|---|
| 1 | 1 | 5000.00 | 1 |
| 2 | 2 | 8000.00 | 2 |
| 3 | 3 | 6000.00 | 3 |

### user_role

**数据行数**: 0
**表大小**: 0.02 MB

#### 字段结构

| 字段名 | 类型 | 是否为空 | 默认值 | 主键 | 自增 | 备注 |
|--------|------|----------|--------|------|------|------|
| role_id | INTEGER | ❌ | - | ❌ | ✅ | None |
| role_name | VARCHAR(100) | ❌ | - | ❌ | ❌ | None |

### user_role_mapping

**数据行数**: 26
**表大小**: 0.03 MB

#### 字段结构

| 字段名 | 类型 | 是否为空 | 默认值 | 主键 | 自增 | 备注 |
|--------|------|----------|--------|------|------|------|
| mapping_id | INTEGER | ❌ | - | ❌ | ✅ | None |
| user_id | INTEGER | ❌ | - | ❌ | ❌ | 用户ID |
| role_id | INTEGER | ❌ | - | ❌ | ❌ | 角色ID |
| company_id | INTEGER | ✅ | - | ❌ | ❌ | 用户所属公司ID |
| is_active | TINYINT | ✅ | - | ❌ | ❌ | 是否启用 |
| created_at | DATETIME | ✅ | - | ❌ | ❌ | None |

#### 索引信息
- **role_id**: 普通索引，字段: role_id

#### 外键关系
- **user_role_mapping_ibfk_1**: role_id → user_roles.role_id

#### 样本数据

| mapping_id | user_id | role_id | company_id | is_active | created_at |
|---|---|---|---|---|---|
| 1 | 1 | 2 | 1 | 1 | 2025-08-15 05:48:36 |
| 2 | 2 | 1 | 2 | 1 | 2025-08-15 05:48:36 |
| 3 | 3 | 2 | 3 | 1 | 2025-08-15 05:48:36 |

### user_roles

**数据行数**: 4
**表大小**: 0.03 MB

#### 字段结构

| 字段名 | 类型 | 是否为空 | 默认值 | 主键 | 自增 | 备注 |
|--------|------|----------|--------|------|------|------|
| role_id | INTEGER | ❌ | - | ❌ | ✅ | None |
| role_name | VARCHAR(50) | ❌ | - | ❌ | ❌ | 角色名称 |
| role_description | TEXT | ✅ | - | ❌ | ❌ | 角色描述 |
| is_active | TINYINT | ✅ | - | ❌ | ❌ | 是否启用 |
| created_at | DATETIME | ✅ | - | ❌ | ❌ | None |
| updated_at | DATETIME | ✅ | - | ❌ | ❌ | None |

#### 索引信息
- **role_name**: 唯一索引，字段: role_name

#### 样本数据

| role_id | role_name | role_description | is_active | created_at | updated_at |
|---|---|---|---|---|---|
| 1 | 管理员 | 系统管理员，拥有所有权限，可以访问所有数据 | 1 | 2025-08-15 05:48:36 | 2025-08-15 05:48:36 |
| 2 | 普通员工 | 普通员工，只能访问自己分公司的数据 | 1 | 2025-08-15 05:48:36 | 2025-08-15 05:48:36 |
| 3 | 部门经理 | 部门经理，可以访问本部门和下属部门数据 | 1 | 2025-08-15 05:48:36 | 2025-08-15 05:48:36 |