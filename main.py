from integrated_permission_controller import RefactoredPermissionController
from sql_parser import SQLTableExtractor
from loguru import logger
import yaml

class TestRunner:
    def __init__(self, config_path: str = "config.yaml"):
        self.controller = RefactoredPermissionController(config_path)
        self.parser = SQLTableExtractor(self.controller.system_tables)
    
    def run_schema_extraction_tests(self):
        """测试schema提取功能 - 修正版"""
        test_cases = [
            "SELECT * FROM employee",
            "SELECT * FROM data_permission_system.employee",  # 使用实际存在的数据库名
            "SELECT * FROM employee e JOIN salary s ON e.user_id = s.user_id",
            "SELECT e.user_name, s.salary FROM employee e LEFT JOIN salary s ON e.user_id = s.user_id"
        ]
        
        for sql in test_cases:
            logger.info(f"\n=== 测试SQL: {sql} ===")
            table_info = self.parser.extract_table_info_with_schema(sql)
            logger.info(f"提取结果: {table_info}")
    
    def run_basic_tests(self):
        """运行基本测试"""
        test_cases = yaml.load(open('test_cases.yaml', encoding='utf-8'), Loader=yaml.FullLoader).get('test_cases', [])
        
        for case in test_cases:
            logger.info(f"\n=== 测试案例: {case['description']} ===")
            result = self.controller.execute_query_with_permissions(case['sql'], case['user_id'])
            logger.info(f"执行结果: {result.execution_result}")
            
            if result.execution_result == 'success':
                logger.info(f"查询数据: {len(result.result)} 条记录")
            else:
                logger.info(f"错误信息: {result.error_message}")

if __name__ == "__main__":
    test_runner = TestRunner()
    test_runner.run_schema_extraction_tests()
    test_runner.run_basic_tests()
