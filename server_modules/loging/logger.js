const fs = require('fs').promises;
const path = require('path');

// Путь к папке с логами и файлам
const logDir = path.join(__dirname, '../../logs');
const olderLogDir = path.join(logDir, 'log_older');
const currentLogFile = path.join(logDir, 'current_log_file.txt');

// Функция логирования с новым форматом временной метки
async function logMessage(message) {
  const now = new Date();
  const year = now.getFullYear();
  const month = String(now.getMonth() + 1).padStart(2, '0');
  const day = String(now.getDate()).padStart(2, '0');
  const hours = String(now.getHours()).padStart(2, '0');
  const minutes = String(now.getMinutes()).padStart(2, '0');
  const timestamp = `[${day}.${month}.${year} | ${hours}.${minutes}]*`;
  const logEntry = `${timestamp} ${message}*\n`;
  try {
    await fs.mkdir(logDir, { recursive: true });
    await fs.appendFile(currentLogFile, logEntry);
  } catch (err) {
    console.error(`Ошибка записи в лог: ${err.message}`);
  }
}

// Функция ротации логов с ограничением в 30 файлов
async function rotateLogs() {
  const maxOldLogs = 30; // Максимальное количество старых логов
  try {
    // Создаём папки logs/ и logs/log_older/
    await fs.mkdir(logDir, { recursive: true });
    await fs.mkdir(olderLogDir, { recursive: true });

    // Проверяем, существует ли текущий лог-файл
    if (await fs.access(currentLogFile).then(() => true).catch(() => false)) {
      // Получаем список старых логов в папке log_older/
      const oldLogs = (await fs.readdir(olderLogDir))
        .filter(file => file.match(/older_log_file_(\d+)\.txt/))
        .map(file => {
          const match = file.match(/older_log_file_(\d+)\.txt/);
          return match ? { file, index: parseInt(match[1]) } : null;
        })
        .filter(item => item)
        .sort((a, b) => a.index - b.index); // Сортируем по возрастанию индекса

      // Удаляем самый старый лог, если их больше maxOldLogs
      if (oldLogs.length >= maxOldLogs) {
        const oldestLog = oldLogs[0]; // Самый старый — с наименьшим индексом
        await fs.unlink(path.join(olderLogDir, oldestLog.file));
        console.log(`Удалён самый старый лог-файл: ${oldestLog.file}`);
        await logMessage(`Удалён самый старый лог-файл: ${oldestLog.file}`);
      }

      // Переименовываем старые логи (увеличиваем их индекс)
      for (let i = oldLogs.length - 1; i >= 0; i--) {
        const oldIndex = oldLogs[i].index;
        const newIndex = oldIndex + 1;
        await fs.rename(
          path.join(olderLogDir, `older_log_file_${oldIndex}.txt`),
          path.join(olderLogDir, `older_log_file_${newIndex}.txt`)
        );
        console.log(`Переименован older_log_file_${oldIndex}.txt → older_log_file_${newIndex}.txt`);
        await logMessage(`Переименован older_log_file_${oldIndex}.txt → older_log_file_${newIndex}.txt`);
      }

      // Перемещаем текущий лог-файл в папку log_older/ с названием older_log_file_1.txt
      await fs.rename(currentLogFile, path.join(olderLogDir, 'older_log_file_1.txt'));
      console.log('current_log_file.txt переименован в older_log_file_1.txt');
      await logMessage('current_log_file.txt переименован в older_log_file_1.txt');
    }

    // Создаём новый пустой лог-файл current_log_file.txt
    await fs.writeFile(currentLogFile, '');
    console.log('Создан новый current_log_file.txt');
    await logMessage('Создан новый current_log_file.txt');
  } catch (err) {
    console.error('Ошибка ротации логов:', err.message);
    await logMessage(`[ERROR] Ошибка ротации логов: ${err.message}`);
  }
}

// Экспортируем функции, чтобы их можно было использовать в других файлах
module.exports = { logMessage, rotateLogs };