#!/usr/bin/env python3
# Nuvrion · release 1.0.0
"""Русский терминальный вывод. Системные настройки этот модуль не меняет."""
import os
import re
import shutil
import sys
import unicodedata

ANSI = re.compile(r'\x1b\[[0-?]*[ -/]*[@-~]')
COLORS = {'ok': '\033[32m', 'warn': '\033[33m', 'error': '\033[31m',
          'info': '\033[36m', 'heading': '\033[1;36m'}


def plain(value):
    return ''.join(c for c in ANSI.sub('', str(value))
                   if c in '\n\t' or (c.isprintable() or unicodedata.combining(c)))


def width(value):
    return sum(0 if unicodedata.combining(c) else
               2 if unicodedata.east_asian_width(c) in ('W', 'F') else 1
               for c in plain(value))


def columns():
    for stream in (sys.stdout, sys.stderr):
        try:
            return max(12, min(100, os.get_terminal_size(stream.fileno()).columns))
        except (OSError, ValueError, AttributeError):
            pass
    return max(12, min(100, shutil.get_terminal_size((80, 24)).columns))


def color(value, kind):
    if not sys.stdout.isatty() or 'NO_COLOR' in os.environ or os.environ.get('TERM') == 'dumb':
        return str(value)
    return COLORS[kind] + str(value) + '\033[0m'


def wrap(value, limit):
    """Перенос по экранной ширине; ANSI исключён, длинные слова разбиваются."""
    result = []
    for paragraph in plain(value).expandtabs(4).splitlines() or ['']:
        line = ''
        for word in paragraph.split():
            if line and width(line + ' ' + word) > limit:
                result.append(line)
                line = ''
            for ch in (' ' if line else '') + word:
                if width(line + ch) > limit:
                    result.append(line)
                    line = ''
                line += ch
        result.append(line)
    return result


def message(value, kind='info'):
    mark = {'ok': '[✓]', 'warn': '[!]', 'error': '[✗]', 'info': '[•]'}[kind]
    for index, line in enumerate(wrap(value, columns() - 6)):
        print(color(('  ' + mark + ' ' if index == 0 else '      ') + line, kind), flush=True)


def heading(value):
    line = '─' * (columns() - 2)
    print('\n' + color('  ' + line, 'heading'))
    for text in wrap(value, columns() - 4):
        print(color('  ' + text, 'heading'))
    print(color('  ' + line, 'heading'), flush=True)


def row(label, state, kind='info'):
    total = columns()
    first = 32 if total >= 72 else max(3, (total - 6) // 2)
    second = max(1, total - first - 4)
    labels, states = wrap(label, first), wrap(state, second)
    for i in range(max(len(labels), len(states))):
        left = labels[i] if i < len(labels) else ''
        right = states[i] if i < len(states) else ''
        print('  ' + left + ' ' * (first - width(left) + 2) + color(right, kind), flush=True)


def filter_log():
    """Оформляет только известные статусы; исходный журнал сохраняется через tee."""
    kinds = {'OK': 'ok', 'ВНИМАНИЕ': 'warn', 'ОШИБКА': 'error',
             'КОНФЛИКТ': 'error', 'ИНФО': 'info', 'ПРОПУСК': 'warn',
             'ИЗМЕНЕНО': 'ok', 'REBOOT': 'warn'}
    summary = False
    for raw in sys.stdin:
        line = plain(raw).strip()
        if 'ИТОГОВЫЙ ОТЧЁТ' in line:
            summary = True
            message('Подробный отчёт тюнинга: /opt/remnanode/tuning-report.log')
            continue
        if summary:
            if 'ПЕРЕЗАГРУЗКА СЕРВЕРА ТРЕБУЕТСЯ' in line:
                summary = False
                heading('Требуется перезагрузка сервера')
            continue
        found = re.match(r'^\[\s*([^]]+?)\s*\]\s*(.*)', line)
        if found and found[1] in kinds:
            message(found[2], kinds[found[1]])
        elif line.startswith('┌─'):
            heading(line[2:].strip().replace('ФИНАЛЬНАЯ ПРОВЕРКА ВСЕХ КОМПОНЕНТОВ',
                                            'Проверка результата тюнинга'))
        elif line and set(line) <= set('─━└╭╮╰╯ '):
            continue
        else:
            for part in wrap(line, columns() - 2):
                print('  ' + part if part else '', flush=True)


if __name__ == '__main__':
    action, *args = sys.argv[1:]
    if action == 'filter':
        filter_log()
    elif action == 'row':
        row(*args)
    elif action == 'heading':
        heading(' '.join(args))
    else:
        message(' '.join(args), action)
