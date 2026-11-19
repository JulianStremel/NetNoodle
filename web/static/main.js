// Entry point. Each page module registers itself with registerView.
// To add a page, write a module and import it here.
import { start } from "./app.js";
import "./devices.js";
import "./peers.js";

start();
