import unittest
import cast.analysers.test
import pydevd
import sqlparse
from sqlparse.sql import IdentifierList, Identifier
from sqlparse.tokens import Keyword, DML

class Test(unittest.TestCase):
    def testRegisterPlugin(self):
        #pydevd.settrace()
        # create a JEE analysis
        analysis = cast.analysers.test.JEETestAnalysis()
        analysis.add_selection('<path of java file to analyze>')
        analysis.add_classpath('C:/Program Files/Java/jre7/lib')
        analysis.add_classpath('C:/Users/PDV/.m2/repository')
        analysis.set_verbose()
        analysis.run()


if __name__ == "__main__":
    unittest.main()