import os
from unittest import TestCase

import casbin
from sqlalchemy import create_engine, Column, Integer, String
from sqlalchemy.orm import sessionmaker

from sqlalchemy_adapter import Adapter
from sqlalchemy_adapter import Base
from sqlalchemy_adapter import CasbinRule
from sqlalchemy_adapter.adapter import Filter, create_casbin_rule_class


def get_fixture(path):
    dir_path = os.path.split(os.path.realpath(__file__))[0] + "/"
    return os.path.abspath(dir_path + path)


def get_enforcer():
    engine = create_engine("sqlite://")
    # engine = create_engine('sqlite:///' + os.path.split(os.path.realpath(__file__))[0] + '/test.db', echo=True)
    adapter = Adapter(engine)

    session = sessionmaker(bind=engine)
    Base.metadata.create_all(engine)
    s = session()
    s.query(CasbinRule).delete()
    s.add(CasbinRule(ptype="p", v0="alice", v1="data1", v2="read"))
    s.add(CasbinRule(ptype="p", v0="bob", v1="data2", v2="write"))
    s.add(CasbinRule(ptype="p", v0="data2_admin", v1="data2", v2="read"))
    s.add(CasbinRule(ptype="p", v0="data2_admin", v1="data2", v2="write"))
    s.add(CasbinRule(ptype="g", v0="alice", v1="data2_admin"))
    s.commit()
    s.close()

    return casbin.Enforcer(get_fixture("rbac_model.conf"), adapter)


def get_custom_table_name_enforcer():
    engine = create_engine("sqlite://")
    table_name = "custom_casbin_rule_table"
    adapter = Adapter(engine, table_name=table_name)

    session = sessionmaker(bind=engine)
    Base.metadata.create_all(engine)
    s = session()

    CustomTableCasbinRule = create_casbin_rule_class(table_name)

    s.query(CustomTableCasbinRule).delete()
    s.add(CustomTableCasbinRule(ptype="p", v0="alice", v1="data1", v2="read"))
    s.commit()
    s.close()

    return casbin.Enforcer(get_fixture("rbac_model.conf"), adapter)


class TestConfig(TestCase):
    def test_custom_db_class(self):
        class CustomRule(Base):
            __tablename__ = "casbin_rule2"

            id = Column(Integer, primary_key=True)
            ptype = Column(String(255))
            v0 = Column(String(255))
            v1 = Column(String(255))
            v2 = Column(String(255))
            v3 = Column(String(255))
            v4 = Column(String(255))
            v5 = Column(String(255))
            not_exist = Column(String(255))

        engine = create_engine("sqlite://")
        adapter = Adapter(engine, CustomRule)

        session = sessionmaker(bind=engine)
        Base.metadata.create_all(engine)
        s = session()
        s.add(CustomRule(not_exist="NotNone"))
        s.commit()
        self.assertEqual(s.query(CustomRule).all()[0].not_exist, "NotNone")

    def test_custom_table_name(self):
        e = get_custom_table_name_enforcer()

        self.assertTrue(e.enforce("alice", "data1", "read"))
        self.assertFalse(e.enforce("bob", "data2", "write"))

    def test_enforcer_basic(self):
        e = get_enforcer()

        self.assertTrue(e.enforce("alice", "data1", "read"))
        self.assertFalse(e.enforce("alice", "data1", "write"))
        self.assertFalse(e.enforce("bob", "data1", "read"))
        self.assertFalse(e.enforce("bob", "data1", "write"))
        self.assertTrue(e.enforce("bob", "data2", "write"))
        self.assertFalse(e.enforce("bob", "data2", "read"))
        self.assertTrue(e.enforce("alice", "data2", "read"))
        self.assertTrue(e.enforce("alice", "data2", "write"))

    def test_add_policy(self):
        e = get_enforcer()

        self.assertFalse(e.enforce("eve", "data3", "read"))
        res = e.add_policies((("eve", "data3", "read"), ("eve", "data4", "read")))
        self.assertTrue(res)
        self.assertTrue(e.enforce("eve", "data3", "read"))
        self.assertTrue(e.enforce("eve", "data4", "read"))

    def test_add_policies(self):
        e = get_enforcer()

        self.assertFalse(e.enforce("eve", "data3", "read"))
        res = e.add_permission_for_user("eve", "data3", "read")
        self.assertTrue(res)
        self.assertTrue(e.enforce("eve", "data3", "read"))

    def test_save_policy(self):
        e = get_enforcer()
        self.assertFalse(e.enforce("alice", "data4", "read"))

        model = e.get_model()
        model.clear_policy()

        model.add_policy("p", "p", ["alice", "data4", "read"])

        adapter = e.get_adapter()
        adapter.save_policy(model)
        self.assertTrue(e.enforce("alice", "data4", "read"))

    def test_remove_policy(self):
        e = get_enforcer()

        self.assertFalse(e.enforce("alice", "data5", "read"))
        e.add_permission_for_user("alice", "data5", "read")
        self.assertTrue(e.enforce("alice", "data5", "read"))
        e.delete_permission_for_user("alice", "data5", "read")
        self.assertFalse(e.enforce("alice", "data5", "read"))

    def test_remove_policies(self):
        e = get_enforcer()

        self.assertFalse(e.enforce("alice", "data5", "read"))
        self.assertFalse(e.enforce("alice", "data6", "read"))
        e.add_policies((("alice", "data5", "read"), ("alice", "data6", "read")))
        self.assertTrue(e.enforce("alice", "data5", "read"))
        self.assertTrue(e.enforce("alice", "data6", "read"))
        e.remove_policies((("alice", "data5", "read"), ("alice", "data6", "read")))
        self.assertFalse(e.enforce("alice", "data5", "read"))
        self.assertFalse(e.enforce("alice", "data6", "read"))

    def test_remove_filtered_policy(self):
        e = get_enforcer()

        self.assertTrue(e.enforce("alice", "data1", "read"))
        e.remove_filtered_policy(1, "data1")
        self.assertFalse(e.enforce("alice", "data1", "read"))

        self.assertTrue(e.enforce("bob", "data2", "write"))
        self.assertTrue(e.enforce("alice", "data2", "read"))
        self.assertTrue(e.enforce("alice", "data2", "write"))

        e.remove_filtered_policy(1, "data2", "read")

        self.assertTrue(e.enforce("bob", "data2", "write"))
        self.assertFalse(e.enforce("alice", "data2", "read"))
        self.assertTrue(e.enforce("alice", "data2", "write"))

        e.remove_filtered_policy(2, "write")

        self.assertFalse(e.enforce("bob", "data2", "write"))
        self.assertFalse(e.enforce("alice", "data2", "write"))

        # e.add_permission_for_user('alice', 'data6', 'delete')
        # e.add_permission_for_user('bob', 'data6', 'delete')
        # e.add_permission_for_user('eve', 'data6', 'delete')
        # self.assertTrue(e.enforce('alice', 'data6', 'delete'))
        # self.assertTrue(e.enforce('bob', 'data6', 'delete'))
        # self.assertTrue(e.enforce('eve', 'data6', 'delete'))
        # e.remove_filtered_policy(0, 'alice', None, 'delete')
        # self.assertFalse(e.enforce('alice', 'data6', 'delete'))
        # e.remove_filtered_policy(0, None, None, 'delete')
        # self.assertFalse(e.enforce('bob', 'data6', 'delete'))
        # self.assertFalse(e.enforce('eve', 'data6', 'delete'))

    def test_str(self):
        rule = CasbinRule(ptype="p", v0="alice", v1="data1", v2="read")
        self.assertEqual(str(rule), "p, alice, data1, read")
        rule = CasbinRule(ptype="p", v0="bob", v1="data2", v2="write")
        self.assertEqual(str(rule), "p, bob, data2, write")
        rule = CasbinRule(ptype="p", v0="data2_admin", v1="data2", v2="read")
        self.assertEqual(str(rule), "p, data2_admin, data2, read")
        rule = CasbinRule(ptype="p", v0="data2_admin", v1="data2", v2="write")
        self.assertEqual(str(rule), "p, data2_admin, data2, write")
        rule = CasbinRule(ptype="g", v0="alice", v1="data2_admin")
        self.assertEqual(str(rule), "g, alice, data2_admin")

    def test_repr(self):
        rule = CasbinRule(ptype="p", v0="alice", v1="data1", v2="read")
        self.assertEqual(repr(rule), '<CasbinRule None: "p, alice, data1, read">')
        engine = create_engine("sqlite://")

        session = sessionmaker(bind=engine)
        Base.metadata.create_all(engine)
        s = session()

        s.add(rule)
        s.commit()
        self.assertRegex(repr(rule), r'<CasbinRule \d+: "p, alice, data1, read">')
        s.close()

    def test_filtered_policy(self):
        e = get_enforcer()
        filter = Filter()

        filter.ptype = ["p"]
        e.load_filtered_policy(filter)
        self.assertTrue(e.enforce("alice", "data1", "read"))
        self.assertFalse(e.enforce("alice", "data1", "write"))
        self.assertFalse(e.enforce("alice", "data2", "read"))
        self.assertFalse(e.enforce("alice", "data2", "write"))
        self.assertFalse(e.enforce("bob", "data1", "read"))
        self.assertFalse(e.enforce("bob", "data1", "write"))
        self.assertFalse(e.enforce("bob", "data2", "read"))
        self.assertTrue(e.enforce("bob", "data2", "write"))

        filter.ptype = []
        filter.v0 = ["alice"]
        e.load_filtered_policy(filter)
        self.assertTrue(e.enforce("alice", "data1", "read"))
        self.assertFalse(e.enforce("alice", "data1", "write"))
        self.assertFalse(e.enforce("alice", "data2", "read"))
        self.assertFalse(e.enforce("alice", "data2", "write"))
        self.assertFalse(e.enforce("bob", "data1", "read"))
        self.assertFalse(e.enforce("bob", "data1", "write"))
        self.assertFalse(e.enforce("bob", "data2", "read"))
        self.assertFalse(e.enforce("bob", "data2", "write"))
        self.assertFalse(e.enforce("data2_admin", "data2", "read"))
        self.assertFalse(e.enforce("data2_admin", "data2", "write"))

        filter.v0 = ["bob"]
        e.load_filtered_policy(filter)
        self.assertFalse(e.enforce("alice", "data1", "read"))
        self.assertFalse(e.enforce("alice", "data1", "write"))
        self.assertFalse(e.enforce("alice", "data2", "read"))
        self.assertFalse(e.enforce("alice", "data2", "write"))
        self.assertFalse(e.enforce("bob", "data1", "read"))
        self.assertFalse(e.enforce("bob", "data1", "write"))
        self.assertFalse(e.enforce("bob", "data2", "read"))
        self.assertTrue(e.enforce("bob", "data2", "write"))
        self.assertFalse(e.enforce("data2_admin", "data2", "read"))
        self.assertFalse(e.enforce("data2_admin", "data2", "write"))

        filter.v0 = ["data2_admin"]
        e.load_filtered_policy(filter)
        self.assertTrue(e.enforce("data2_admin", "data2", "read"))
        self.assertTrue(e.enforce("data2_admin", "data2", "read"))
        self.assertFalse(e.enforce("alice", "data1", "read"))
        self.assertFalse(e.enforce("alice", "data1", "write"))
        self.assertFalse(e.enforce("alice", "data2", "read"))
        self.assertFalse(e.enforce("alice", "data2", "write"))
        self.assertFalse(e.enforce("bob", "data1", "read"))
        self.assertFalse(e.enforce("bob", "data1", "write"))
        self.assertFalse(e.enforce("bob", "data2", "read"))
        self.assertFalse(e.enforce("bob", "data2", "write"))

        filter.v0 = ["alice", "bob"]
        e.load_filtered_policy(filter)
        self.assertTrue(e.enforce("alice", "data1", "read"))
        self.assertFalse(e.enforce("alice", "data1", "write"))
        self.assertFalse(e.enforce("alice", "data2", "read"))
        self.assertFalse(e.enforce("alice", "data2", "write"))
        self.assertFalse(e.enforce("bob", "data1", "read"))
        self.assertFalse(e.enforce("bob", "data1", "write"))
        self.assertFalse(e.enforce("bob", "data2", "read"))
        self.assertTrue(e.enforce("bob", "data2", "write"))
        self.assertFalse(e.enforce("data2_admin", "data2", "read"))
        self.assertFalse(e.enforce("data2_admin", "data2", "write"))

        filter.v0 = []
        filter.v1 = ["data1"]
        e.load_filtered_policy(filter)
        self.assertTrue(e.enforce("alice", "data1", "read"))
        self.assertFalse(e.enforce("alice", "data1", "write"))
        self.assertFalse(e.enforce("alice", "data2", "read"))
        self.assertFalse(e.enforce("alice", "data2", "write"))
        self.assertFalse(e.enforce("bob", "data1", "read"))
        self.assertFalse(e.enforce("bob", "data1", "write"))
        self.assertFalse(e.enforce("bob", "data2", "read"))
        self.assertFalse(e.enforce("bob", "data2", "write"))
        self.assertFalse(e.enforce("data2_admin", "data2", "read"))
        self.assertFalse(e.enforce("data2_admin", "data2", "write"))

        filter.v1 = ["data2"]
        e.load_filtered_policy(filter)
        self.assertFalse(e.enforce("alice", "data1", "read"))
        self.assertFalse(e.enforce("alice", "data1", "write"))
        self.assertFalse(e.enforce("alice", "data2", "read"))
        self.assertFalse(e.enforce("alice", "data2", "write"))
        self.assertFalse(e.enforce("bob", "data1", "read"))
        self.assertFalse(e.enforce("bob", "data1", "write"))
        self.assertFalse(e.enforce("bob", "data2", "read"))
        self.assertTrue(e.enforce("bob", "data2", "write"))
        self.assertTrue(e.enforce("data2_admin", "data2", "read"))
        self.assertTrue(e.enforce("data2_admin", "data2", "write"))

        filter.v1 = []
        filter.v2 = ["read"]
        e.load_filtered_policy(filter)
        self.assertTrue(e.enforce("alice", "data1", "read"))
        self.assertFalse(e.enforce("alice", "data1", "write"))
        self.assertFalse(e.enforce("alice", "data2", "read"))
        self.assertFalse(e.enforce("alice", "data2", "write"))
        self.assertFalse(e.enforce("bob", "data1", "read"))
        self.assertFalse(e.enforce("bob", "data1", "write"))
        self.assertFalse(e.enforce("bob", "data2", "read"))
        self.assertFalse(e.enforce("bob", "data2", "write"))
        self.assertTrue(e.enforce("data2_admin", "data2", "read"))
        self.assertFalse(e.enforce("data2_admin", "data2", "write"))

        filter.v2 = ["write"]
        e.load_filtered_policy(filter)
        self.assertFalse(e.enforce("alice", "data1", "read"))
        self.assertFalse(e.enforce("alice", "data1", "write"))
        self.assertFalse(e.enforce("alice", "data2", "read"))
        self.assertFalse(e.enforce("alice", "data2", "write"))
        self.assertFalse(e.enforce("bob", "data1", "read"))
        self.assertFalse(e.enforce("bob", "data1", "write"))
        self.assertFalse(e.enforce("bob", "data2", "read"))
        self.assertTrue(e.enforce("bob", "data2", "write"))
        self.assertFalse(e.enforce("data2_admin", "data2", "read"))
        self.assertTrue(e.enforce("data2_admin", "data2", "write"))

    def test_update_policy(self):
        e = get_enforcer()
        example_p = ["mike", "cookie", "eat"]

        self.assertTrue(e.enforce("alice", "data1", "read"))
        e.update_policy(["alice", "data1", "read"], ["alice", "data1", "no_read"])
        self.assertFalse(e.enforce("alice", "data1", "read"))

        self.assertFalse(e.enforce("bob", "data1", "read"))
        e.add_policy(example_p)
        e.update_policy(example_p, ["bob", "data1", "read"])
        self.assertTrue(e.enforce("bob", "data1", "read"))

        self.assertFalse(e.enforce("bob", "data1", "write"))
        e.update_policy(["bob", "data1", "read"], ["bob", "data1", "write"])
        self.assertTrue(e.enforce("bob", "data1", "write"))

        self.assertTrue(e.enforce("bob", "data2", "write"))
        e.update_policy(["bob", "data2", "write"], ["bob", "data2", "read"])
        self.assertFalse(e.enforce("bob", "data2", "write"))

        self.assertTrue(e.enforce("bob", "data2", "read"))
        e.update_policy(["bob", "data2", "read"], ["carl", "data2", "write"])
        self.assertFalse(e.enforce("bob", "data2", "write"))

        self.assertTrue(e.enforce("carl", "data2", "write"))
        e.update_policy(["carl", "data2", "write"], ["carl", "data2", "no_write"])
        self.assertFalse(e.enforce("bob", "data2", "write"))

    def test_update_policies(self):
        e = get_enforcer()

        old_rule_0 = ["alice", "data1", "read"]
        old_rule_1 = ["bob", "data2", "write"]
        old_rule_2 = ["data2_admin", "data2", "read"]
        old_rule_3 = ["data2_admin", "data2", "write"]

        new_rule_0 = ["alice", "data_test", "read"]
        new_rule_1 = ["bob", "data_test", "write"]
        new_rule_2 = ["data2_admin", "data_test", "read"]
        new_rule_3 = ["data2_admin", "data_test", "write"]

        old_rules = [old_rule_0, old_rule_1, old_rule_2, old_rule_3]
        new_rules = [new_rule_0, new_rule_1, new_rule_2, new_rule_3]

        e.update_policies(old_rules, new_rules)

        self.assertFalse(e.enforce("alice", "data1", "read"))
        self.assertTrue(e.enforce("alice", "data_test", "read"))

        self.assertFalse(e.enforce("bob", "data2", "write"))
        self.assertTrue(e.enforce("bob", "data_test", "write"))

        self.assertFalse(e.enforce("data2_admin", "data2", "read"))
        self.assertTrue(e.enforce("data2_admin", "data_test", "read"))

        self.assertFalse(e.enforce("data2_admin", "data2", "write"))
        self.assertTrue(e.enforce("data2_admin", "data_test", "write"))

    def test_update_filtered_policies(self):
        e = get_enforcer()

        e.update_filtered_policies(
            [
                ["data2_admin", "data3", "read"],
                ["data2_admin", "data3", "write"],
            ],
            0,
            "data2_admin",
        )
        self.assertTrue(e.enforce("data2_admin", "data3", "write"))
        self.assertTrue(e.enforce("data2_admin", "data3", "read"))

        e.update_filtered_policies([["alice", "data1", "write"]], 0, "alice")
        self.assertTrue(e.enforce("alice", "data1", "write"))

        e.update_filtered_policies([["bob", "data2", "read"]], 0, "bob")
        self.assertTrue(e.enforce("bob", "data2", "read"))

    def test_create_table_false(self):
        """Test that tables are not created when create_table=False"""
        from sqlalchemy import inspect

        engine = create_engine("sqlite://")

        # Create adapter with create_table=False
        adapter = Adapter(engine, create_table=False)

        # Verify that the table was NOT created
        inspector = inspect(engine)
        tables = inspector.get_table_names()
        self.assertEqual(
            len(tables), 0, "No tables should be created when create_table=False"
        )

    def test_create_table_true_default(self):
        """Test that tables are created by default (backward compatibility)"""
        from sqlalchemy import inspect

        engine = create_engine("sqlite://")

        # Create adapter without specifying create_table (should default to True)
        adapter = Adapter(engine)

        # Verify that the table WAS created
        inspector = inspect(engine)
        tables = inspector.get_table_names()
        self.assertIn("casbin_rule", tables, "Table should be created by default")

    def test_create_table_custom_table_name(self):
        """Test that custom table name is not created when create_table=False"""
        from sqlalchemy import inspect

        engine = create_engine("sqlite://")
        table_name = "my_custom_table"

        # Create adapter with custom table name and create_table=False
        adapter = Adapter(engine, table_name=table_name, create_table=False)

        # Verify that the table was NOT created
        inspector = inspect(engine)
        tables = inspector.get_table_names()
        self.assertEqual(
            len(tables), 0, "No tables should be created when create_table=False"
        )

    def test_create_table_custom_db_class(self):
        """Test that custom db_class table is not created when create_table=False"""
        from sqlalchemy import inspect

        class CustomRule(Base):
            __tablename__ = "custom_rule_table"

            id = Column(Integer, primary_key=True)
            ptype = Column(String(255))
            v0 = Column(String(255))
            v1 = Column(String(255))
            v2 = Column(String(255))
            v3 = Column(String(255))
            v4 = Column(String(255))
            v5 = Column(String(255))

        engine = create_engine("sqlite://")

        # Create adapter with custom db_class and create_table=False
        adapter = Adapter(engine, db_class=CustomRule, create_table=False)

        # Verify that the table was NOT created
        inspector = inspect(engine)
        tables = inspector.get_table_names()
        self.assertEqual(
            len(tables), 0, "No tables should be created when create_table=False"
        )
