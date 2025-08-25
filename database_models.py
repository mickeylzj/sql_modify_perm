# database_models.py

from sqlalchemy import create_engine, Column, Integer, String, Text, Boolean, DateTime, Enum as SQLEnum, ForeignKey, DECIMAL
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship
from datetime import datetime
import enum
import json

Base = declarative_base()

class Employee(Base):
    """员工信息表"""
    __tablename__ = 'employee'
    
    user_id = Column(Integer, primary_key=True, autoincrement=True, comment='用户ID')
    user_name = Column(String(100), nullable=False, comment='用户姓名')
    company_id = Column(Integer, nullable=False, comment='公司ID')
    role = Column(String(50), nullable=False, comment='默认角色')
    
    # 可选：如果有Company表，可以建立关系
    # company = relationship("Company", back_populates="employees")

class Company(Base):
    """公司信息表"""
    __tablename__ = 'company'
    
    company_id = Column(Integer, primary_key=True, autoincrement=True, comment='公司ID')
    company_name = Column(String(100), nullable=False, comment='公司名称')
    
    # employees = relationship("Employee", back_populates="company")

class Salary(Base):
    """薪资信息表"""
    __tablename__ = 'salary'
    
    salary_id = Column(Integer, primary_key=True, autoincrement=True, comment='薪资ID')
    user_id = Column(Integer, ForeignKey('employee.user_id'), nullable=False, comment='用户ID')
    amount = Column(DECIMAL(10, 2), nullable=False, comment='薪资金额')
    company_id = Column(Integer, ForeignKey('company.company_id'), nullable=False, comment='公司ID')

class Age(Base):
    """年龄信息表"""
    __tablename__ = 'age'
    
    age_id = Column(Integer, primary_key=True, autoincrement=True, comment='年龄记录ID')
    user_id = Column(Integer, ForeignKey('employee.user_id'), nullable=False, comment='用户ID')
    age = Column(Integer, nullable=False, comment='年龄')

class PermissionType(enum.Enum):
    """权限类型枚举"""
    TABLE_LEVEL = "table_level"      # 表级权限
    ROW_LEVEL = "row_level"          # 行级权限
    COLUMN_LEVEL = "column_level"    # 列级权限（预留）

class FilterType(enum.Enum):
    """过滤类型枚举"""
    ALLOW_ALL = "allow_all"          # 允许全部访问
    DENY_ALL = "deny_all"            # 拒绝全部访问
    CUSTOM_SQL = "custom_sql"        # 自定义SQL过滤

class PermissionRule(Base):
    """权限规则配置表"""
    __tablename__ = 'permission_rules'
    
    rule_id = Column(Integer, primary_key=True, autoincrement=True, comment='规则ID')
    rule_name = Column(String(100), nullable=False, comment='规则名称')
    table_name = Column(String(100), nullable=False, comment='表名，*表示所有表')
    permission_type = Column(SQLEnum(PermissionType), nullable=False, comment='权限类型')
    filter_type = Column(SQLEnum(FilterType), nullable=False, comment='过滤类型')
    filter_sql = Column(Text, comment='自定义过滤SQL，支持占位符，如 (role=\'$role\' AND user_id=\'$user_id\') OR (role=\'总经理\' AND company_id=\'$company_id\')')
    target_roles = Column(Text, comment='适用角色列表，JSON格式存储，如 ["员工", "总经理"]')
    view_template = Column(Text, comment='视图模板，支持CTE视图定义，如 "xx_{table_name} AS (SELECT * FROM {table_name} WHERE {filter_sql})"')  # 新增：支持视图模板
    is_active = Column(Boolean, default=True, comment='是否启用')
    priority = Column(Integer, default=0, comment='优先级，数字越大优先级越高')
    created_at = Column(DateTime, default=datetime.utcnow, comment='创建时间')
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, comment='更新时间')
    description = Column(Text, comment='规则描述')

class UserRole(Base):
    """用户角色表"""
    __tablename__ = 'user_roles'
    
    role_id = Column(Integer, primary_key=True, autoincrement=True)
    role_name = Column(String(50), nullable=False, unique=True, comment='角色名称')
    role_description = Column(Text, comment='角色描述')
    is_active = Column(Boolean, default=True, comment='是否启用')
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class UserRoleMapping(Base):
    """用户角色映射表"""
    __tablename__ = 'user_role_mapping'
    
    mapping_id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(Integer, nullable=False, comment='用户ID')
    role_id = Column(Integer, ForeignKey('user_roles.role_id'), nullable=False, comment='角色ID')
    company_id = Column(Integer, comment='用户所属公司ID')
    is_active = Column(Boolean, default=True, comment='是否启用')
    created_at = Column(DateTime, default=datetime.utcnow)
    
    # 建立关系
    role = relationship("UserRole", backref="user_mappings")

class PermissionLog(Base):
    """权限访问日志表"""
    __tablename__ = 'permission_logs'
    
    log_id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(Integer, nullable=False, comment='用户ID')
    original_sql = Column(Text, comment='原始SQL')
    modified_sql = Column(Text, comment='修改后SQL')
    table_names = Column(Text, comment='涉及的表名，JSON格式')
    execution_result = Column(String(20), comment='执行结果：success/failed/denied')
    execution_time = Column(Integer, comment='执行时间（毫秒）')
    error_message = Column(Text, comment='错误信息')
    created_at = Column(DateTime, default=datetime.utcnow)
