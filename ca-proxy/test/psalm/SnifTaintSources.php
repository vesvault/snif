<?php
/*
 * A Psalm plugin: the CA proxy's inputs, as taint sources, for Psalm's
 * taint analysis (README beside this file).
 *
 * Psalm treats no $_SERVER value and not the request body as input, and
 * the CA proxy's input is nearly all there: the URI, the Host and the other
 * headers, and the body of a CSR. This marks as input any expression that
 * holds one of these:
 *   - $_SERVER, or any value read from it. That includes DOCUMENT_ROOT,
 *     which the web server sets: the paths built on it are findings, read
 *     and kept in the baseline. Marking only some keys loses the input
 *     assigned straight from $_SERVER, which Psalm does not follow.
 *   - file_get_contents('php://input'), the body;
 *   - an index into the arrays that hold preg_match() captures of request
 *     or remote input (CAPTURES), since Psalm loses taint through a
 *     capture. A new such array in the CA proxy goes in the list.
 * Psalm asks about whole expressions (a concatenation, an argument), so an
 * expression is input if any part of it is.
 *
 * Psalm does not follow input through $GLOBALS, nor the body once assigned
 * to a variable, and symlink() is not a sink for it.
 */
namespace SnifTaint;

use Psalm\Plugin\EventHandler\AddTaintsInterface;
use Psalm\Plugin\EventHandler\Event\AddRemoveTaintsEvent;
use Psalm\Type\TaintKindGroup;
use PsalmPhar\PhpParser\Node;
use PsalmPhar\PhpParser\Node\Expr\ArrayDimFetch;
use PsalmPhar\PhpParser\Node\Expr\ArrowFunction;
use PsalmPhar\PhpParser\Node\Expr\Closure;
use PsalmPhar\PhpParser\Node\Expr\FuncCall;
use PsalmPhar\PhpParser\Node\Expr\Variable;
use PsalmPhar\PhpParser\Node\Name;
use PsalmPhar\PhpParser\Node\Scalar\String_;

final class Sources implements AddTaintsInterface
{
    private const CAPTURES = ['rm', 'm', 'rspp'];

    public static function addTaints(AddRemoveTaintsEvent $event): array
    {
        return self::hasSource($event->getExpr(), 0) ? TaintKindGroup::ALL_INPUT : [];
    }

    private static function isSourceVar(Node $e): bool
    {
        return $e instanceof Variable && is_string($e->name)
            && ($e->name === '_SERVER' || in_array($e->name, self::CAPTURES, true));
    }

    private static function hasSource(Node $e, int $depth): bool
    {
        if ($depth > 12 || $e instanceof Closure || $e instanceof ArrowFunction) {
            return false;
        }
        if (self::isSourceVar($e) || ($e instanceof ArrayDimFetch && self::isSourceVar($e->var))) {
            return true;
        }
        if ($e instanceof FuncCall && $e->name instanceof Name
            && strtolower($e->name->toString()) === 'file_get_contents'
            && isset($e->args[0]) && $e->args[0]->value instanceof String_
            && $e->args[0]->value->value === 'php://input') {
            return true;
        }
        foreach ($e->getSubNodeNames() as $name) {
            $sub = $e->$name;
            foreach (is_array($sub) ? $sub : [$sub] as $s) {
                if ($s instanceof Node && self::hasSource($s, $depth + 1)) {
                    return true;
                }
            }
        }
        return false;
    }
}
