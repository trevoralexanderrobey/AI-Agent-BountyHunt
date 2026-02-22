@echo off
setlocal
set APP_DIR=%~dp0
if exist "%JAVA_HOME%\\bin\\java.exe" (
  set JAVA_EXE=%JAVA_HOME%\\bin\\java.exe
) else (
  set JAVA_EXE=java
)

"%JAVA_EXE%" -classpath "%APP_DIR%\\gradle\\wrapper\\gradle-wrapper.jar" org.gradle.wrapper.GradleWrapperMain %*
endlocal

