from HashDemoWindow import HashDemoWindow
import sys
from PyQt5.QtWidgets import QApplication


app = QApplication(sys.argv)

#full features
w = HashDemoWindow()
w.show()
sys.exit(app.exec_())