import hmac
import json
import re
import os

import snowflake.connector

from runners.helpers import db, dbconfig

from flask import Blueprint, request, jsonify
import logbook

logger = logbook.Logger(__name__)

rules_api = Blueprint('rules', __name__)

SECRET = os.environ.get("SECRET", "")


def unindent(text):
    "if beginning and every newline followed by spaces, removes them"
    indent = min(len(x) for x in re.findall('^( *)', text, flags=re.M | re.I))
    return text if indent == 0 else re.sub(f'^{" " * indent}', '', text, flags=re.M)


@rules_api.route('', methods=['GET'])
def get_rules():
    logger.info('>>>>>>>>>>>>')
    return jsonify(rules=[])


@rules_api.route('', methods=['POST'])
def create_rule():
    if not hmac.compare_digest(request.cookies.get("sid", ""), SECRET):
        return jsonify(success=False, message="bad sid", rule={})

    data = request.get_json()
    rule_title, rule_type, rule_target, rule_body = (
        data['title'],
        data['type'],
        data['target'],
        data['body'],
    )
    logger.info(f'Creating rule {rule_title}_{rule_target}_{rule_type}')

    # support for full queries with comments frontend sends comments
    rule_body = re.sub(r"^CREATE [^\n]+\n", "", rule_body, flags=re.I)
    m = re.match(r"^  COMMENT='((?:\\'|[^'])*)'\nAS\n", rule_body)
    comment, rule_body = (
        (m.group(1), rule_body[m.span()[1] :]) if m else ('', rule_body)
    )
    comment_clause = f"\n  COMMENT='{comment}'\n"

    view_name = f"rules.{rule_title}_{rule_target}_{rule_type}"
    rule_body = (
        f"CREATE OR REPLACE VIEW {view_name} COPY GRANTS{comment_clause}AS\n{rule_body}"
    )

    try:
        oauth = json.loads(request.headers.get('Authorization') or '{}')
        ctx = db.connect(oauth=oauth)
        ctx.cursor().execute(rule_body).fetchall()

        try:  # errors expected, e.g. if permissions managed by future grants on schema
            ctx.cursor().execute(
                f"GRANT SELECT ON VIEW {view_name} TO ROLE {dbconfig.ROLE}"
            ).fetchall()
        except Exception:
            pass

        if 'body' in data and 'savedBody' in data:
            data['savedBody'] = rule_body

        data['results'] = (
            list(db.fetch(ctx, f"SELECT * FROM {view_name};"))
            if view_name.endswith("_POLICY_DEFINITION")
            else None
        )

    except snowflake.connector.errors.ProgrammingError as e:
        return jsonify(success=False, message=e.msg, rule=data)

    return jsonify(success=True, rule=data)


@rules_api.route('/delete', methods=['POST'])
def delete_rule():
    if not hmac.compare_digest(request.cookies.get("sid", ""), SECRET):
        return jsonify(success=False, message="bad sid", rule={})

    data = request.get_json()
    rule_title, rule_type, rule_target, rule_body = (
        data['title'],
        data['type'],
        data['target'],
        data['body'],
    )
    logger.info(f'Deleting rule {rule_title}_{rule_target}_{rule_type}')

    try:
        oauth = json.loads(request.headers.get('Authorization') or '{}')
        ctx = db.connect(oauth=oauth)
        view_name = f"{rule_title}_{rule_target}_{rule_type}"
        new_view_name = f"{rule_title}_{rule_target}_{rule_type}_DELETED"
        ctx.cursor().execute(
            f"""ALTER VIEW rules.{view_name} RENAME TO rules.{new_view_name}"""
        ).fetchall()
        if 'body' in data and 'savedBody' in data:
            data['savedBody'] = rule_body
    except snowflake.connector.errors.ProgrammingError as e:
        return jsonify(success=False, message=e.msg, rule=data)

    return jsonify(success=True, view_name=view_name, rule=data)


@rules_api.route('/rename', methods=['POST'])
def rename_rule():
    if not hmac.compare_digest(request.cookies.get("sid", ""), SECRET):
        return jsonify(success=False, message="bad sid", rule={})

    data = request.get_json()
    rule_title, rule_type, rule_target, new_title = (
        data['title'],
        data['type'],
        data['target'],
        data['newTitle'],
    )
    logger.info(f'Renaming rule {rule_title}_{rule_target}_{rule_type}')

    try:
        oauth = json.loads(request.headers.get('Authorization') or '{}')
        ctx = db.connect(oauth=oauth)
        view_name = f"{rule_title}_{rule_target}_{rule_type}"
        new_view_name = f"{new_title}_{rule_target}_{rule_type}"
        ctx.cursor().execute(
            f"""ALTER VIEW rules.{view_name} RENAME TO rules.{new_view_name}"""
        ).fetchall()
    except snowflake.connector.errors.ProgrammingError as e:
        return jsonify(success=False, message=e.msg, rule=data)

    return jsonify(success=True, rule=data)
